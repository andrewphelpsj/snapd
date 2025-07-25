// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package backend_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/boot"
	"github.com/snapcore/snapd/boot/boottest"
	"github.com/snapcore/snapd/bootloader"
	"github.com/snapcore/snapd/bootloader/bootloadertest"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/gadget/device"
	"github.com/snapcore/snapd/overlord/fdestate/backend"
	"github.com/snapcore/snapd/secboot"
	"github.com/snapcore/snapd/testutil"
)

type encryptedContainer struct {
	uuid          string
	containerRole string
	legacyKeys    map[string]string
}

func (disk *encryptedContainer) ContainerRole() string {
	return disk.containerRole
}

func (disk *encryptedContainer) LegacyKeys() map[string]string {
	return disk.legacyKeys
}

func (disk *encryptedContainer) DevPath() string {
	return fmt.Sprintf("/dev/disk/by-uuid/%s", disk.uuid)
}

func isChainPresent(allowed []*secboot.LoadChain, files []bootloader.BootFile) bool {
	if len(files) == 0 {
		return len(allowed) == 0
	}

	current := files[0]
	for _, c := range allowed {
		if current.Path == c.Path && current.Snap == c.Snap && current.Role == c.Role {
			if isChainPresent(c.Next, files[1:]) {
				return true
			}
		}
	}

	return false
}

type containsChainChecker struct {
	*CheckerInfo
}

var ContainsChain Checker = &containsChainChecker{
	&CheckerInfo{Name: "ContainsChain", Params: []string{"chainscontainer", "chain"}},
}

func (c *containsChainChecker) Check(params []any, names []string) (result bool, error string) {
	allowed, ok := params[0].([]*secboot.LoadChain)
	if !ok {
		return false, "Wrong type for chain container"
	}
	bootFiles, ok := params[1].([]bootloader.BootFile)
	if !ok {
		return false, "Wrong type for boot file chain"
	}
	result = isChainPresent(allowed, bootFiles)
	if !result {
		error = fmt.Sprintf("Chain %v is not present in allowed boot chains", bootFiles)
	}
	return result, error
}

func removeKernelBootFiles(bootChains []boot.BootChain) []boot.BootChain {
	var ret []boot.BootChain
	for _, v := range bootChains {
		v.KernelBootFile = bootloader.BootFile{}
		ret = append(ret, v)
	}
	return ret
}

func mockAssetsCache(c *C, rootdir, bootloaderName string, cachedAssets []string) {
	p := filepath.Join(dirs.SnapBootAssetsDirUnder(rootdir), bootloaderName)
	err := os.MkdirAll(p, 0755)
	c.Assert(err, IsNil)
	for _, cachedAsset := range cachedAssets {
		err = os.WriteFile(filepath.Join(p, cachedAsset), nil, 0644)
		c.Assert(err, IsNil)
	}
}

type resealTestSuite struct {
	testutil.BaseTest

	rootdir string
}

var _ = Suite(&resealTestSuite{})

func (s *resealTestSuite) SetUpTest(c *C) {
	s.rootdir = c.MkDir()
	dirs.SetRootDir(s.rootdir)
	s.AddCleanup(func() { dirs.SetRootDir("/") })
}

type fakeState struct {
	state               map[string]*backend.SealingParameters
	isUnlocked          bool
	hasUnlocked         int
	EncryptedContainers []backend.EncryptedContainer
}

func (fs *fakeState) Update(role string, containerRole string, params *backend.SealingParameters) error {
	if fs.state == nil {
		fs.state = make(map[string]*backend.SealingParameters)
	}
	fs.state[fmt.Sprintf("%s|%s", role, containerRole)] = params
	return nil
}

func (fs *fakeState) Get(role string, containerRole string) (params *backend.SealingParameters, err error) {
	if fs.state == nil {
		fs.state = make(map[string]*backend.SealingParameters)
	}
	p, hasParameters := fs.state[fmt.Sprintf("%s|%s", role, containerRole)]
	if !hasParameters {
		p, hasParameters = fs.state[fmt.Sprintf("%s|all", role)]
	}
	if !hasParameters {
		return nil, nil
	}
	return p, nil
}

func (fs *fakeState) Unlock() (relock func()) {
	fs.isUnlocked = true
	fs.hasUnlocked++
	return func() {
		fs.isUnlocked = false
	}
}

func (fs *fakeState) GetEncryptedContainers() ([]backend.EncryptedContainer, error) {
	if fs.EncryptedContainers == nil {
		return nil, fmt.Errorf("EncryptedContainers were not set")
	}
	return fs.EncryptedContainers, nil
}

type fakeSealedKey struct {
	num int
}

func (s *resealTestSuite) testTPMResealHappy(c *C, revokeOldKeys bool, missingRunParams bool, missingRecoverParams bool, onClassic bool) {
	bl := bootloadertest.Mock("trusted", "").WithTrustedAssets()
	bootloader.Force(bl)
	defer bootloader.Force(nil)

	bl.TrustedAssetsMap = map[string]string{
		"asset": "asset",
		"shim":  "shim",
	}
	recoveryKernel := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)
	runKernel := bootloader.NewBootFile(filepath.Join(s.rootdir, "var/lib/snapd/snaps/pc-kernel_500.snap"), "kernel.efi", bootloader.RoleRunMode)
	shimBf := bootloader.NewBootFile("", filepath.Join(dirs.SnapBootAssetsDir, "trusted", "shim-shimhash"), bootloader.RoleRecovery)
	assetBf := bootloader.NewBootFile("", filepath.Join(dirs.SnapBootAssetsDir, "trusted", "asset-assethash"), bootloader.RoleRecovery)
	runAssetBf := bootloader.NewBootFile("", filepath.Join(dirs.SnapBootAssetsDir, "trusted", "asset-runassethash"), bootloader.RoleRunMode)

	bl.RecoveryBootChainList = []bootloader.BootFile{
		bootloader.NewBootFile("", "shim", bootloader.RoleRecovery),
		bootloader.NewBootFile("", "asset", bootloader.RoleRecovery),
		recoveryKernel,
	}
	bl.BootChainList = []bootloader.BootFile{
		bootloader.NewBootFile("", "shim", bootloader.RoleRecovery),
		bootloader.NewBootFile("", "asset", bootloader.RoleRecovery),
		bootloader.NewBootFile("", "asset", bootloader.RoleRunMode),
		runKernel,
	}

	c.Assert(os.MkdirAll(filepath.Join(dirs.SnapBootAssetsDir, "trusted"), 0755), IsNil)
	for _, name := range []string{
		"shim-shimhash",
		"asset-runassethash",
		"asset-assethash",
	} {
		err := os.WriteFile(filepath.Join(dirs.SnapBootAssetsDir, "trusted", name), nil, 0644)
		c.Assert(err, IsNil)
	}

	bootIsResealNeededCalls := 0
	defer backend.MockBootIsResealNeeded(func(pbc boot.PredictableBootChains, bootChainsFile string, expectReseal bool) (ok bool, nextCount int, err error) {
		bootIsResealNeededCalls++
		switch bootIsResealNeededCalls {
		case 1:
			if missingRunParams {
				return false, 0, nil
			}
		case 2:
			if missingRecoverParams {
				return false, 0, nil
			}
		}

		return boot.IsResealNeeded(pbc, bootChainsFile, expectReseal)
	})()

	var model *asserts.Model
	if onClassic {
		model = boottest.MakeMockClassicWithModesModel()
	} else {
		model = boottest.MakeMockUC20Model()
	}

	bootChains := boot.BootChains{
		RunModeBootChains: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),

				AssetChain: []boot.BootAsset{
					{
						Role: bootloader.RoleRecovery,
						Name: "shim",
						Hashes: []string{
							"shimhash",
						},
					},
					{
						Role: bootloader.RoleRecovery,
						Name: "asset",
						Hashes: []string{
							"assethash",
						},
					},
					{
						Role: bootloader.RoleRunMode,
						Name: "asset",
						Hashes: []string{
							"runassethash",
						},
					},
				},

				Kernel:         "kernel.efi",
				KernelRevision: "500",
				KernelCmdlines: []string{
					"mode=run",
				},
				KernelBootFile: runKernel,
			},
		},

		RecoveryBootChainsForRunKey: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),

				AssetChain: []boot.BootAsset{
					{
						Role: bootloader.RoleRecovery,
						Name: "shim",
						Hashes: []string{
							"shimhash",
						},
					},
					{
						Role: bootloader.RoleRecovery,
						Name: "asset",
						Hashes: []string{
							"assethash",
						},
					},
				},

				Kernel:         "kernel.efi",
				KernelRevision: "1",
				KernelCmdlines: []string{
					"mode=recover",
				},
				KernelBootFile: recoveryKernel,
			},
		},

		RecoveryBootChains: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),

				AssetChain: []boot.BootAsset{
					{
						Role: bootloader.RoleRecovery,
						Name: "shim",
						Hashes: []string{
							"shimhash",
						},
					},
					{
						Role: bootloader.RoleRecovery,
						Name: "asset",
						Hashes: []string{
							"assethash",
						},
					},
				},

				Kernel:         "kernel.efi",
				KernelRevision: "1",
				KernelCmdlines: []string{
					"mode=recover",
				},
				KernelBootFile: recoveryKernel,
			},
		},

		RoleToBlName: map[bootloader.Role]string{
			bootloader.RoleRecovery: "trusted",
			bootloader.RoleRunMode:  "trusted",
		},
	}

	buildProfileCalls := 0
	restore := backend.MockSecbootBuildPCRProtectionProfile(func(modelParams []*secboot.SealKeyModelParams, allowInsufficientDmaProtection bool) (secboot.SerializedPCRProfile, error) {
		buildProfileCalls++

		c.Check(allowInsufficientDmaProtection, Equals, !onClassic)

		c.Assert(modelParams, HasLen, 1)
		mp := modelParams[0]
		c.Check(mp.Model.Model(), Equals, model.Model())
		switch buildProfileCalls {
		case 1:
			if !missingRunParams {
				c.Check(mp.EFILoadChains, DeepEquals, []*secboot.LoadChain{
					secboot.NewLoadChain(shimBf,
						secboot.NewLoadChain(assetBf,
							secboot.NewLoadChain(recoveryKernel))),
					secboot.NewLoadChain(shimBf,
						secboot.NewLoadChain(assetBf,
							secboot.NewLoadChain(runAssetBf,
								secboot.NewLoadChain(runKernel)))),
				})
			}
		case 2:
			c.Check(mp.EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shimBf,
					secboot.NewLoadChain(assetBf,
						secboot.NewLoadChain(runAssetBf,
							secboot.NewLoadChain(runKernel)))),
			})
		case 3:
			c.Check(mp.EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shimBf,
					secboot.NewLoadChain(assetBf,
						secboot.NewLoadChain(recoveryKernel))),
			})
		default:
			c.Errorf("unexpected additional call to secboot.BuildPCRProtectionProfile (call # %d)", buildProfileCalls)
		}
		return []byte(`"serialized-pcr-profile"`), nil
	})
	defer restore()

	resealCalls := 0
	restore = backend.MockSecbootResealKeys(func(params *secboot.ResealKeysParams, newPCRPolicyVersion bool) (secboot.UpdatedKeys, error) {
		resealCalls++

		skippedCalls := 0
		if missingRunParams {
			skippedCalls += 1
		}

		c.Check(params.PrimaryKey, DeepEquals, []byte{1, 2, 3, 4})
		c.Check(newPCRPolicyVersion, Equals, revokeOldKeys && !missingRunParams && !missingRecoverParams)

		c.Check(params.PCRProfile, DeepEquals, secboot.SerializedPCRProfile(`"serialized-pcr-profile"`))
		switch resealCalls + skippedCalls {
		case 1:
			// Resealing the run+recover key for data partition
			c.Check(params.Keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/123",
					SlotName:   "default",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				},
			})
		case 2:
			// Resealing the recovery key for both data partition
			c.Check(params.Keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/123",
					SlotName:   "default-fallback",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
				},
			})
		case 3:
			// Resealing the recovery key for both save partition
			c.Check(params.Keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/456",
					SlotName:   "default-fallback",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
				},
			})
		default:
			c.Errorf("unexpected additional call to secboot.ResealKey (call # %d)", resealCalls)
		}
		return secboot.UpdatedKeys([]secboot.MaybeSealedKeyData{&fakeSealedKey{num: resealCalls}}), nil
	})
	defer restore()

	myState := &fakeState{}
	myState.EncryptedContainers = []backend.EncryptedContainer{
		&encryptedContainer{
			uuid:          "123",
			containerRole: "system-data",
			legacyKeys: map[string]string{
				"default":          filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
			},
		},
		&encryptedContainer{
			uuid:          "456",
			containerRole: "system-save",
			legacyKeys: map[string]string{
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
			},
		},
	}

	defer backend.MockSecbootGetPrimaryKey(func(devices []string, fallbackKeyFile string) ([]byte, error) {
		c.Check(fallbackKeyFile, Equals, filepath.Join(dirs.SnapSaveDir, "device/fde", "tpm-policy-auth-key"))
		c.Check(devices, DeepEquals, []string{"/dev/disk/by-uuid/123", "/dev/disk/by-uuid/456"})
		return []byte{1, 2, 3, 4}, nil
	})()

	defer backend.MockSecbootRevokeOldKeys(func(uk *secboot.UpdatedKeys, primaryKey []byte) error {
		if !revokeOldKeys {
			c.Errorf("unexpected call")
			return fmt.Errorf("unexpected call")
		}
		c.Assert(uk, NotNil)
		c.Assert(*uk, HasLen, 3)
		c.Check((*uk)[0].(*fakeSealedKey).num, Equals, 1)
		c.Check((*uk)[1].(*fakeSealedKey).num, Equals, 2)
		c.Check((*uk)[2].(*fakeSealedKey).num, Equals, 3)
		c.Check(primaryKey, DeepEquals, []byte{1, 2, 3, 4})

		return nil
	})()

	opts := boot.ResealKeyToModeenvOptions{ExpectReseal: true, RevokeOldKeys: revokeOldKeys}
	err := backend.ResealKeyForBootChains(myState, device.SealingMethodTPM, s.rootdir, &boot.ResealKeyForBootChainsParams{BootChains: bootChains, Options: opts})
	c.Assert(err, IsNil)

	c.Assert(bootIsResealNeededCalls, Equals, 2)

	expectedResealCalls := 3
	if missingRunParams {
		expectedResealCalls -= 1
	}
	if missingRecoverParams {
		expectedResealCalls -= 2
	}
	c.Check(resealCalls, Equals, expectedResealCalls)

	pbc, cnt, err := boot.ReadBootChains(filepath.Join(dirs.SnapFDEDir, "boot-chains"))
	c.Assert(err, IsNil)
	if !missingRunParams {
		c.Assert(cnt, Equals, 1)
		c.Check(pbc, DeepEquals, boot.ToPredictableBootChains(removeKernelBootFiles(append(bootChains.RunModeBootChains, bootChains.RecoveryBootChainsForRunKey...))))
	}

	recoveryPbc, cnt, err := boot.ReadBootChains(filepath.Join(dirs.SnapFDEDir, "recovery-boot-chains"))
	c.Assert(err, IsNil)
	if !missingRecoverParams {
		c.Check(recoveryPbc, DeepEquals, boot.ToPredictableBootChains(removeKernelBootFiles(bootChains.RecoveryBootChains)))
		c.Assert(cnt, Equals, 1)
	}
}

func (s *resealTestSuite) TestTPMResealHappy(c *C) {
	const revokeOldKeys = false
	const missingRunParams = false
	const missingRecoverParams = false
	const onClassic = true
	s.testTPMResealHappy(c, revokeOldKeys, missingRunParams, missingRecoverParams, onClassic)
}

func (s *resealTestSuite) TestTPMResealHappyCore(c *C) {
	const revokeOldKeys = false
	const missingRunParams = false
	const missingRecoverParams = false
	const onClassic = false
	s.testTPMResealHappy(c, revokeOldKeys, missingRunParams, missingRecoverParams, onClassic)
}

func (s *resealTestSuite) TestTPMResealHappyRevoke(c *C) {
	const revokeOldKeys = true
	const missingRunParams = false
	const missingRecoverParams = false
	const onClassic = true
	s.testTPMResealHappy(c, revokeOldKeys, missingRunParams, missingRecoverParams, onClassic)
}

func (s *resealTestSuite) TestTPMResealHappyRevokeMissingRunParams(c *C) {
	const revokeOldKeys = true
	const missingRunParams = true
	const missingRecoverParams = false
	const onClassic = true
	s.testTPMResealHappy(c, revokeOldKeys, missingRunParams, missingRecoverParams, onClassic)
}

func (s *resealTestSuite) TestTPMResealHappyRevokeMissingRecoverParams(c *C) {
	const revokeOldKeys = true
	const missingRunParams = false
	const missingRecoverParams = true
	const onClassic = true
	s.testTPMResealHappy(c, revokeOldKeys, missingRunParams, missingRecoverParams, onClassic)
}

func (s *resealTestSuite) TestTPMResealHappyRevokeMissingParams(c *C) {
	const revokeOldKeys = true
	const missingRunParams = true
	const missingRecoverParams = true
	const onClassic = true
	s.testTPMResealHappy(c, revokeOldKeys, missingRunParams, missingRecoverParams, onClassic)
}

func (s *resealTestSuite) TestResealKeyForBootchainsWithSystemFallback(c *C) {
	var prevPbc boot.PredictableBootChains
	var prevRecoveryPbc boot.PredictableBootChains
	myState := &fakeState{}

	for idx, tc := range []struct {
		reuseRunPbc      bool
		reuseRecoveryPbc bool
		resealErr        error
		shimId           string
		shimId2          string
		noShim2          bool
		grubId           string
		grubId2          string
		noGrub2          bool
		runGrubId        string
		err              string
	}{
		{shimId: "bootx64.efi", grubId: "grubx64.efi", resealErr: nil, err: ""},
		{shimId: "bootx64.efi", grubId: "grubx64.efi", resealErr: nil, err: ""},
		{shimId2: "bootx64.efi", grubId2: "grubx64.efi", resealErr: nil, err: ""},
		{shimId: "bootx64.efi", grubId: "grubx64.efi", shimId2: "ubuntu:shimx64.efi", grubId2: "ubuntu:grubx64.efi", resealErr: nil, err: ""},
		{noGrub2: true, resealErr: nil, err: ""},
		{noShim2: true, resealErr: nil, err: ""},
		{noShim2: true, noGrub2: true, resealErr: nil, err: ""},
		{resealErr: nil, err: ""},
		{resealErr: errors.New("reseal error"), err: "cannot reseal the encryption key: reseal error"},
		{reuseRunPbc: true, reuseRecoveryPbc: true, resealErr: nil, err: ""},
		// recovery boot chain is unchanged
		{reuseRunPbc: false, reuseRecoveryPbc: true, resealErr: nil, err: ""},
		// run boot chain is unchanged
		{reuseRunPbc: true, reuseRecoveryPbc: false, resealErr: nil, err: ""},
	} {
		c.Logf("tc: %v", idx)
		rootdir := c.MkDir()
		dirs.SetRootDir(rootdir)
		defer dirs.SetRootDir("/")

		myState.EncryptedContainers = []backend.EncryptedContainer{
			&encryptedContainer{
				uuid:          "123",
				containerRole: "system-data",
				legacyKeys: map[string]string{
					"default":          filepath.Join(rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
					"default-fallback": filepath.Join(rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
				},
			},
			&encryptedContainer{
				uuid:          "456",
				containerRole: "system-save",
				legacyKeys: map[string]string{
					"default-fallback": filepath.Join(rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
				},
			},
		}

		shimId := tc.shimId
		if shimId == "" {
			shimId = "ubuntu:shimx64.efi"
		}
		shimId2 := tc.shimId2
		if shimId2 == "" && !tc.noShim2 {
			shimId2 = shimId
		}
		grubId := tc.grubId
		if grubId == "" {
			grubId = "ubuntu:grubx64.efi"
		}
		grubId2 := tc.grubId2
		if grubId2 == "" && !tc.noGrub2 {
			grubId2 = grubId
		}
		runGrubId := tc.runGrubId
		if runGrubId == "" {
			runGrubId = "grubx64.efi"
		}

		var expectedCache []string
		expectedCache = append(expectedCache, fmt.Sprintf("%s-shim-hash-1", shimId))
		if shimId2 != "" {
			expectedCache = append(expectedCache, fmt.Sprintf("%s-shim-hash-2", shimId2))
		}
		expectedCache = append(expectedCache, fmt.Sprintf("%s-grub-hash-1", grubId))
		if grubId2 != "" {
			expectedCache = append(expectedCache, fmt.Sprintf("%s-grub-hash-2", grubId2))
		}

		expectedCache = append(expectedCache,
			fmt.Sprintf("%s-run-grub-hash-1", runGrubId),
			fmt.Sprintf("%s-run-grub-hash-2", runGrubId),
		)

		if tc.reuseRunPbc {
			err := boot.WriteBootChains(prevPbc, filepath.Join(dirs.SnapFDEDir, "boot-chains"), 9)
			c.Assert(err, IsNil)
		}
		if tc.reuseRecoveryPbc {
			err := boot.WriteBootChains(prevRecoveryPbc, filepath.Join(dirs.SnapFDEDir, "recovery-boot-chains"), 9)
			c.Assert(err, IsNil)
		}

		// mock asset cache
		mockAssetsCache(c, rootdir, "grub", expectedCache)

		buildProfileCalls := 0
		restore := backend.MockSecbootBuildPCRProtectionProfile(func(modelParams []*secboot.SealKeyModelParams, allowInsufficientDmaProtection bool) (secboot.SerializedPCRProfile, error) {
			buildProfileCalls++

			c.Check(allowInsufficientDmaProtection, Equals, true)

			c.Assert(modelParams, HasLen, 1)
			// shared parameters
			c.Assert(modelParams[0].Model.Model(), Equals, "my-model-uc20")

			// recovery parameters
			shim := bootloader.NewBootFile("", filepath.Join(rootdir, fmt.Sprintf("var/lib/snapd/boot-assets/grub/%s-shim-hash-1", shimId)), bootloader.RoleRecovery)
			shim2 := bootloader.NewBootFile("", filepath.Join(rootdir, fmt.Sprintf("var/lib/snapd/boot-assets/grub/%s-shim-hash-2", shimId2)), bootloader.RoleRecovery)
			grub := bootloader.NewBootFile("", filepath.Join(rootdir, fmt.Sprintf("var/lib/snapd/boot-assets/grub/%s-grub-hash-1", grubId)), bootloader.RoleRecovery)
			grub2 := bootloader.NewBootFile("", filepath.Join(rootdir, fmt.Sprintf("var/lib/snapd/boot-assets/grub/%s-grub-hash-2", grubId2)), bootloader.RoleRecovery)
			kernel := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)
			// run mode parameters
			runGrub := bootloader.NewBootFile("", filepath.Join(rootdir, fmt.Sprintf("var/lib/snapd/boot-assets/grub/%s-run-grub-hash-1", runGrubId)), bootloader.RoleRunMode)
			runGrub2 := bootloader.NewBootFile("", filepath.Join(rootdir, fmt.Sprintf("var/lib/snapd/boot-assets/grub/%s-run-grub-hash-2", runGrubId)), bootloader.RoleRunMode)
			runKernel := bootloader.NewBootFile(filepath.Join(rootdir, "var/lib/snapd/snaps/pc-kernel_500.snap"), "kernel.efi", bootloader.RoleRunMode)
			runKernel2 := bootloader.NewBootFile(filepath.Join(rootdir, "var/lib/snapd/snaps/pc-kernel_600.snap"), "kernel.efi", bootloader.RoleRunMode)

			var possibleChains [][]bootloader.BootFile
			for _, possibleRunKernel := range []bootloader.BootFile{runKernel, runKernel2} {
				possibleChains = append(possibleChains, []bootloader.BootFile{
					shim,
					grub,
					runGrub,
					possibleRunKernel,
				})
				possibleChains = append(possibleChains, []bootloader.BootFile{
					shim,
					grub,
					runGrub2,
					possibleRunKernel,
				})
				if grubId2 != "" {
					if shimId2 == shimId {
						// We keep the same boot chain so, shim -> grub2 is possible.
						possibleChains = append(possibleChains, []bootloader.BootFile{
							shim,
							grub2,
							runGrub2,
							possibleRunKernel,
						})
					}
					if shimId2 != "" {
						possibleChains = append(possibleChains, []bootloader.BootFile{
							shim2,
							grub2,
							runGrub2,
							possibleRunKernel,
						})
					}
				} else if shimId2 != "" {
					// We should not test the case where we half update, to a completely new bootchain.
					c.Assert(shimId, Equals, shimId2)

					possibleChains = append(possibleChains, []bootloader.BootFile{
						shim2,
						grub,
						runGrub2,
						possibleRunKernel,
					})
				}
			}

			var possibleRecoveryChains [][]bootloader.BootFile
			possibleRecoveryChains = append(possibleRecoveryChains, []bootloader.BootFile{
				shim,
				grub,
				kernel,
			})
			if grubId2 != "" {
				if shimId2 == shimId {
					// We keep the same boot chain so, shim -> grub2 is possible.
					possibleRecoveryChains = append(possibleRecoveryChains, []bootloader.BootFile{
						shim,
						grub2,
						kernel,
					})
				}
				if shimId2 != "" {
					possibleRecoveryChains = append(possibleRecoveryChains, []bootloader.BootFile{
						shim2,
						grub2,
						kernel,
					})
				}
			} else if shimId2 != "" {
				// We should not test the case where we half update, to a completely new bootchain.
				c.Assert(shimId, Equals, shimId2)

				possibleRecoveryChains = append(possibleRecoveryChains, []bootloader.BootFile{
					shim2,
					grub,
					kernel,
				})
			}

			checkRunParams := func() {
				c.Check(modelParams[0].KernelCmdlines, DeepEquals, []string{
					"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
					"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
				})

				for _, chain := range possibleChains {
					c.Check(modelParams[0].EFILoadChains, ContainsChain, chain)
				}
				for _, chain := range possibleRecoveryChains {
					c.Check(modelParams[0].EFILoadChains, ContainsChain, chain)
				}
			}

			checkRunOnlyParams := func() {
				c.Check(modelParams[0].KernelCmdlines, DeepEquals, []string{
					"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
				})

				for _, chain := range possibleChains {
					c.Check(modelParams[0].EFILoadChains, ContainsChain, chain)
				}
			}

			checkRecoveryParams := func() {
				c.Check(modelParams[0].KernelCmdlines, DeepEquals, []string{
					"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				})
				for _, chain := range possibleRecoveryChains {
					c.Check(modelParams[0].EFILoadChains, ContainsChain, chain)
				}
			}

			switch buildProfileCalls {
			case 1:
				if !tc.reuseRunPbc {
					checkRunParams()
				} else if !tc.reuseRecoveryPbc {
					checkRecoveryParams()
				} else {
					c.Errorf("unexpected call to secboot.BuildPCRProtectionProfile (call # %d)", buildProfileCalls)
				}
			case 2:
				if !tc.reuseRunPbc {
					checkRunOnlyParams()
				} else if !tc.reuseRecoveryPbc {
					checkRecoveryParams()
				} else {
					c.Errorf("unexpected call to secboot.BuildPCRProtectionProfile (call # %d)", buildProfileCalls)
				}
			case 3:
				if !tc.reuseRecoveryPbc {
					checkRecoveryParams()
				} else {
					c.Errorf("unexpected call to secboot.BuildPCRProtectionProfile (call # %d)", buildProfileCalls)
				}
			default:
				c.Errorf("unexpected additional call to secboot.BuildPCRProtectionProfile (call # %d)", buildProfileCalls)
			}

			return []byte(`"serialized-pcr-profile"`), nil
		})
		defer restore()

		// set mock key resealing
		resealKeysCalls := 0
		restore = backend.MockSecbootResealKeys(func(params *secboot.ResealKeysParams, newPCRPolicyVersion bool) (secboot.UpdatedKeys, error) {
			c.Check(params.PrimaryKey, DeepEquals, []byte{1, 2, 3, 4})
			c.Check(newPCRPolicyVersion, Equals, false)

			resealKeysCalls++
			c.Check(params.PCRProfile, DeepEquals, secboot.SerializedPCRProfile(`"serialized-pcr-profile"`))

			checkRunParams := func() {
				c.Check(params.Keys, DeepEquals, []secboot.KeyDataLocation{
					{
						DevicePath: "/dev/disk/by-uuid/123",
						SlotName:   "default",
						KeyFile:    filepath.Join(boot.InitramfsBootEncryptionKeyDir, "ubuntu-data.sealed-key"),
					},
				})
			}

			checkRecoveryParamsData := func() {
				c.Check(params.Keys, DeepEquals, []secboot.KeyDataLocation{
					{
						DevicePath: "/dev/disk/by-uuid/123",
						SlotName:   "default-fallback",
						KeyFile:    filepath.Join(boot.InitramfsSeedEncryptionKeyDir, "ubuntu-data.recovery.sealed-key"),
					},
				})
			}

			checkRecoveryParamsSave := func() {
				c.Check(params.Keys, DeepEquals, []secboot.KeyDataLocation{
					{
						DevicePath: "/dev/disk/by-uuid/456",
						SlotName:   "default-fallback",
						KeyFile:    filepath.Join(boot.InitramfsSeedEncryptionKeyDir, "ubuntu-save.recovery.sealed-key"),
					},
				})
			}

			switch resealKeysCalls {
			case 1:
				checkRunParams()
			case 2:
				checkRecoveryParamsData()
			case 3:
				checkRecoveryParamsSave()
			default:
				c.Errorf("unexpected additional call to secboot.ResealKeys (call # %d)", resealKeysCalls)
			}

			return nil, tc.resealErr
		})
		defer restore()

		kernel := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)
		runKernel := bootloader.NewBootFile(filepath.Join(rootdir, "var/lib/snapd/snaps/pc-kernel_500.snap"), "kernel.efi", bootloader.RoleRunMode)
		runKernel2 := bootloader.NewBootFile(filepath.Join(rootdir, "var/lib/snapd/snaps/pc-kernel_600.snap"), "kernel.efi", bootloader.RoleRunMode)

		var runBootChains []boot.BootChain
		var recoveryBootChainsForRun []boot.BootChain
		var recoveryBootChains []boot.BootChain
		var shimHashes []string
		shimHashes = append(shimHashes, "shim-hash-1")
		if shimId2 != "" && shimId2 == shimId {
			shimHashes = append(shimHashes, "shim-hash-2")
		}
		var grubHashes []string
		grubHashes = append(grubHashes, "grub-hash-1")
		if grubId2 != "" && grubId2 == grubId {
			grubHashes = append(grubHashes, "grub-hash-2")
		}
		recoveryBootChains = append(recoveryBootChains,
			boot.BootChain{
				BrandID:        "my-brand",
				Model:          "my-model-uc20",
				Grade:          "dangerous",
				ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
				AssetChain: []boot.BootAsset{
					{
						Role:   bootloader.RoleRecovery,
						Name:   shimId,
						Hashes: shimHashes,
					},
					{
						Role:   bootloader.RoleRecovery,
						Name:   grubId,
						Hashes: grubHashes,
					},
				},
				Kernel:         "pc-kernel",
				KernelRevision: "1",
				KernelCmdlines: []string{
					"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				},
				KernelBootFile: kernel,
			},
		)
		recoveryBootChainsForRun = append(recoveryBootChainsForRun,
			boot.BootChain{
				BrandID:        "my-brand",
				Model:          "my-model-uc20",
				Grade:          "dangerous",
				ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
				AssetChain: []boot.BootAsset{
					{
						Role:   bootloader.RoleRecovery,
						Name:   shimId,
						Hashes: shimHashes,
					},
					{
						Role:   bootloader.RoleRecovery,
						Name:   grubId,
						Hashes: grubHashes,
					},
				},
				Kernel:         "pc-kernel",
				KernelRevision: "1",
				KernelCmdlines: []string{
					"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				},
				KernelBootFile: kernel,
			},
		)
		runBootChains = append(runBootChains,
			boot.BootChain{
				BrandID:        "my-brand",
				Model:          "my-model-uc20",
				Grade:          "dangerous",
				ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
				AssetChain: []boot.BootAsset{
					{
						Role:   bootloader.RoleRecovery,
						Name:   shimId,
						Hashes: shimHashes,
					},
					{
						Role:   bootloader.RoleRecovery,
						Name:   grubId,
						Hashes: grubHashes,
					},
					{
						Role:   bootloader.RoleRunMode,
						Name:   runGrubId,
						Hashes: []string{"run-grub-hash-1", "run-grub-hash-2"},
					},
				},
				Kernel:         "pc-kernel",
				KernelRevision: "500",
				KernelCmdlines: []string{
					"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
				},
				KernelBootFile: runKernel,
			},
			boot.BootChain{
				BrandID:        "my-brand",
				Model:          "my-model-uc20",
				Grade:          "dangerous",
				ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
				AssetChain: []boot.BootAsset{
					{
						Role:   bootloader.RoleRecovery,
						Name:   shimId,
						Hashes: shimHashes,
					},
					{
						Role:   bootloader.RoleRecovery,
						Name:   grubId,
						Hashes: grubHashes,
					},
					{
						Role:   bootloader.RoleRunMode,
						Name:   runGrubId,
						Hashes: []string{"run-grub-hash-1", "run-grub-hash-2"},
					},
				},
				Kernel:         "pc-kernel",
				KernelRevision: "600",
				KernelCmdlines: []string{
					"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
				},
				KernelBootFile: runKernel2,
			},
		)
		if shimId2 != "" && shimId2 != shimId && grubId2 != "" && grubId2 != grubId {
			extraRecoveryBootChains := []boot.BootChain{
				{
					BrandID:        "my-brand",
					Model:          "my-model-uc20",
					Grade:          "dangerous",
					ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
					AssetChain: []boot.BootAsset{
						{
							Role:   bootloader.RoleRecovery,
							Name:   shimId2,
							Hashes: []string{"shim-hash-2"},
						},
						{
							Role:   bootloader.RoleRecovery,
							Name:   grubId2,
							Hashes: []string{"grub-hash-2"},
						},
					},
					Kernel:         "pc-kernel",
					KernelRevision: "1",
					KernelCmdlines: []string{
						"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
					},
					KernelBootFile: kernel,
				},
			}
			extraRecoveryBootChainsForRun := []boot.BootChain{
				{
					BrandID:        "my-brand",
					Model:          "my-model-uc20",
					Grade:          "dangerous",
					ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
					AssetChain: []boot.BootAsset{
						{
							Role:   bootloader.RoleRecovery,
							Name:   shimId2,
							Hashes: []string{"shim-hash-2"},
						},
						{
							Role:   bootloader.RoleRecovery,
							Name:   grubId2,
							Hashes: []string{"grub-hash-2"},
						},
					},
					Kernel:         "pc-kernel",
					KernelRevision: "1",
					KernelCmdlines: []string{
						"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
					},
					KernelBootFile: kernel,
				},
			}
			extraRunBootChains := []boot.BootChain{
				{
					BrandID:        "my-brand",
					Model:          "my-model-uc20",
					Grade:          "dangerous",
					ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
					AssetChain: []boot.BootAsset{
						{
							Role:   bootloader.RoleRecovery,
							Name:   shimId2,
							Hashes: []string{"shim-hash-2"},
						},
						{
							Role:   bootloader.RoleRecovery,
							Name:   grubId2,
							Hashes: []string{"grub-hash-2"},
						},
						{
							Role:   bootloader.RoleRunMode,
							Name:   runGrubId,
							Hashes: []string{"run-grub-hash-1", "run-grub-hash-2"},
						},
					},
					Kernel:         "pc-kernel",
					KernelRevision: "500",
					KernelCmdlines: []string{
						"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
					},
					KernelBootFile: runKernel,
				},
				{
					BrandID:        "my-brand",
					Model:          "my-model-uc20",
					Grade:          "dangerous",
					ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
					AssetChain: []boot.BootAsset{
						{
							Role:   bootloader.RoleRecovery,
							Name:   shimId2,
							Hashes: []string{"shim-hash-2"},
						},
						{
							Role:   bootloader.RoleRecovery,
							Name:   grubId2,
							Hashes: []string{"grub-hash-2"},
						},
						{
							Role:   bootloader.RoleRunMode,
							Name:   runGrubId,
							Hashes: []string{"run-grub-hash-1", "run-grub-hash-2"},
						},
					},
					Kernel:         "pc-kernel",
					KernelRevision: "600",
					KernelCmdlines: []string{
						"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
					},
					KernelBootFile: runKernel2,
				},
			}
			// Let's try to simulate the correct behavior of the caller, where the older chains are always before newer ones
			if shimId == "bootx64.efi" {
				recoveryBootChains = append(recoveryBootChains, extraRecoveryBootChains...)
				recoveryBootChainsForRun = append(recoveryBootChainsForRun, extraRecoveryBootChainsForRun...)
				runBootChains = append(runBootChains, extraRunBootChains...)
			} else {
				recoveryBootChains = append(extraRecoveryBootChains, recoveryBootChains...)
				recoveryBootChainsForRun = append(extraRecoveryBootChainsForRun, recoveryBootChainsForRun...)
				runBootChains = append(extraRunBootChains, runBootChains...)
			}

		}

		bootChains := boot.BootChains{
			RunModeBootChains:           runBootChains,
			RecoveryBootChainsForRunKey: recoveryBootChainsForRun,
			RecoveryBootChains:          recoveryBootChains,
			RoleToBlName: map[bootloader.Role]string{
				bootloader.RoleRunMode:  "grub",
				bootloader.RoleRecovery: "grub",
			},
		}

		defer backend.MockSecbootGetPrimaryKey(func(devices []string, fallbackKeyFile string) ([]byte, error) {
			c.Check(fallbackKeyFile, Equals, filepath.Join(dirs.SnapSaveDir, "device/fde", "tpm-policy-auth-key"))
			c.Check(devices, DeepEquals, []string{"/dev/disk/by-uuid/123", "/dev/disk/by-uuid/456"})
			return []byte{1, 2, 3, 4}, nil
		})()

		err := backend.ResealKeyForBootChains(myState, device.SealingMethodTPM, rootdir, &boot.ResealKeyForBootChainsParams{BootChains: bootChains})
		if tc.err == "" {
			c.Assert(err, IsNil)
		} else {
			c.Assert(err, ErrorMatches, tc.err)
		}
		if tc.resealErr != nil {
			// mocked error is returned on first reseal
			c.Assert(resealKeysCalls, Equals, 1)
		} else {
			c.Assert(resealKeysCalls, Equals, 3)
		}
		if tc.err != "" {
			continue
		}

		// verify the boot chains data file
		pbc, cnt, err := boot.ReadBootChains(filepath.Join(dirs.SnapFDEDir, "boot-chains"))
		c.Assert(err, IsNil)
		if tc.reuseRunPbc {
			c.Assert(cnt, Equals, 9)
		} else {
			c.Assert(cnt, Equals, 1)
		}
		c.Check(pbc, DeepEquals, boot.PredictableBootChains(removeKernelBootFiles(append(recoveryBootChainsForRun, runBootChains...))))

		prevPbc = pbc
		recoveryPbc, cnt, err := boot.ReadBootChains(filepath.Join(dirs.SnapFDEDir, "recovery-boot-chains"))
		c.Assert(err, IsNil)
		if tc.reuseRecoveryPbc {
			c.Check(cnt, Equals, 9)
		} else {
			c.Check(cnt, Equals, 1)
		}
		prevRecoveryPbc = recoveryPbc
		c.Check(recoveryPbc, DeepEquals, boot.PredictableBootChains(removeKernelBootFiles(recoveryBootChains)))
	}
}

func (s *resealTestSuite) TestResealKeyForBootchainsRecoveryKeysForGoodSystemsOnly(c *C) {
	// mock asset cache
	mockAssetsCache(c, s.rootdir, "grub", []string{
		"bootx64.efi-shim-hash",
		"grubx64.efi-grub-hash",
		"grubx64.efi-run-grub-hash",
	})

	buildProfileCalls := 0
	restore := backend.MockSecbootBuildPCRProtectionProfile(func(modelParams []*secboot.SealKeyModelParams, allowInsufficientDmaProtection bool) (secboot.SerializedPCRProfile, error) {
		buildProfileCalls++

		c.Check(allowInsufficientDmaProtection, Equals, true)

		// shared parameters
		c.Assert(modelParams[0].Model.Model(), Equals, "my-model-uc20")

		switch buildProfileCalls {
		case 1: // run key
			c.Assert(modelParams[0].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=factory-reset snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=1234 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
			})
			// load chains
			c.Assert(modelParams[0].EFILoadChains, HasLen, 3)
		case 2: // run only key
			c.Assert(modelParams[0].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
			})
			// load chains
			c.Assert(modelParams[0].EFILoadChains, HasLen, 1)
		case 3: // recovery keys
			c.Assert(modelParams[0].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=factory-reset snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
			})
			// load chains
			c.Assert(modelParams[0].EFILoadChains, HasLen, 1)
		default:
			c.Errorf("unexpected additional call to secboot.BuildPCRProtectionProfile (call # %d)", buildProfileCalls)
		}

		// recovery parameters
		shim := bootloader.NewBootFile("", filepath.Join(s.rootdir, "var/lib/snapd/boot-assets/grub/bootx64.efi-shim-hash"), bootloader.RoleRecovery)
		grub := bootloader.NewBootFile("", filepath.Join(s.rootdir, "var/lib/snapd/boot-assets/grub/grubx64.efi-grub-hash"), bootloader.RoleRecovery)
		kernelGoodRecovery := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)
		// kernel from a tried recovery system
		kernelTriedRecovery := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_999.snap", "kernel.efi", bootloader.RoleRecovery)
		// run mode parameters
		runGrub := bootloader.NewBootFile("", filepath.Join(s.rootdir, "var/lib/snapd/boot-assets/grub/grubx64.efi-run-grub-hash"), bootloader.RoleRunMode)
		runKernel := bootloader.NewBootFile(filepath.Join(s.rootdir, "var/lib/snapd/snaps/pc-kernel_500.snap"), "kernel.efi", bootloader.RoleRunMode)

		switch buildProfileCalls {
		case 1: // run load chain
			c.Assert(modelParams[0].EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(kernelGoodRecovery),
					)),
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(kernelTriedRecovery),
					)),
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(runGrub,
							secboot.NewLoadChain(runKernel)),
					)),
			})
		case 2: // run load chain
			c.Assert(modelParams[0].EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(runGrub,
							secboot.NewLoadChain(runKernel)),
					)),
			})
		case 3: // recovery load chains
			c.Assert(modelParams[0].EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(kernelGoodRecovery),
					)),
			})
		}

		return []byte(`"serialized-pcr-profile"`), nil
	})
	defer restore()

	// set mock key resealing
	resealKeysCalls := 0
	restore = backend.MockSecbootResealKeys(func(params *secboot.ResealKeysParams, newPCRPolicyVersion bool) (secboot.UpdatedKeys, error) {
		c.Check(params.PrimaryKey, DeepEquals, []byte{1, 2, 3, 4})
		c.Check(newPCRPolicyVersion, Equals, false)

		resealKeysCalls++
		c.Check(params.PCRProfile, DeepEquals, secboot.SerializedPCRProfile(`"serialized-pcr-profile"`))

		switch resealKeysCalls {
		case 1: // run key
			c.Assert(params.Keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/123",
					SlotName:   "default",
					KeyFile:    filepath.Join(boot.InitramfsBootEncryptionKeyDir, "ubuntu-data.sealed-key"),
				},
			})
		case 2: // recovery keys
			c.Check(params.Keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/123",
					SlotName:   "default-fallback",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
				},
			})
		case 3:
			c.Check(params.Keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/456",
					SlotName:   "default-fallback",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
				},
			})
		default:
			c.Errorf("unexpected additional call to secboot.ResealKeys (call # %d)", resealKeysCalls)
		}

		return nil, nil
	})
	defer restore()

	kernelGoodRecovery := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)
	kernelTriedRecovery := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_999.snap", "kernel.efi", bootloader.RoleRecovery)
	runKernel := bootloader.NewBootFile(filepath.Join(s.rootdir, "var/lib/snapd/snaps/pc-kernel_500.snap"), "kernel.efi", bootloader.RoleRunMode)

	runBootChains := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   bootloader.RoleRecovery,
					Name:   "bootx64.efi",
					Hashes: []string{"shim-hash"},
				},
				{
					Role:   bootloader.RoleRecovery,
					Name:   "grubx64.efi",
					Hashes: []string{"grub-hash"},
				},
				{
					Role:   bootloader.RoleRunMode,
					Name:   "grubx64.efi",
					Hashes: []string{"run-grub-hash"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "500",
			KernelCmdlines: []string{
				"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
			},
			KernelBootFile: runKernel,
		},
	}

	recoveryBootChainsForRun := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   bootloader.RoleRecovery,
					Name:   "bootx64.efi",
					Hashes: []string{"shim-hash"},
				},
				{
					Role:   bootloader.RoleRecovery,
					Name:   "grubx64.efi",
					Hashes: []string{"grub-hash"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "1",
			KernelCmdlines: []string{
				"snapd_recovery_mode=factory-reset snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
			},
			KernelBootFile: kernelGoodRecovery,
		},
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   bootloader.RoleRecovery,
					Name:   "bootx64.efi",
					Hashes: []string{"shim-hash"},
				},
				{
					Role:   bootloader.RoleRecovery,
					Name:   "grubx64.efi",
					Hashes: []string{"grub-hash"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "999",
			KernelCmdlines: []string{
				// but only the recover mode
				"snapd_recovery_mode=recover snapd_recovery_system=1234 console=ttyS0 console=tty1 panic=-1",
			},
			KernelBootFile: kernelTriedRecovery,
		},
	}

	recoveryBootChains := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   bootloader.RoleRecovery,
					Name:   "bootx64.efi",
					Hashes: []string{"shim-hash"},
				},
				{
					Role:   bootloader.RoleRecovery,
					Name:   "grubx64.efi",
					Hashes: []string{"grub-hash"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "1",
			KernelCmdlines: []string{
				"snapd_recovery_mode=factory-reset snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
			},
			KernelBootFile: kernelGoodRecovery,
		},
	}

	bootChains := boot.BootChains{
		RunModeBootChains:           runBootChains,
		RecoveryBootChainsForRunKey: recoveryBootChainsForRun,
		RecoveryBootChains:          recoveryBootChains,
		RoleToBlName: map[bootloader.Role]string{
			bootloader.RoleRunMode:  "grub",
			bootloader.RoleRecovery: "grub",
		},
	}

	myState := &fakeState{}
	myState.EncryptedContainers = []backend.EncryptedContainer{
		&encryptedContainer{
			uuid:          "123",
			containerRole: "system-data",
			legacyKeys: map[string]string{
				"default":          filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
			},
		},
		&encryptedContainer{
			uuid:          "456",
			containerRole: "system-save",
			legacyKeys: map[string]string{
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
			},
		},
	}

	defer backend.MockSecbootGetPrimaryKey(func(devices []string, fallbackKeyFile string) ([]byte, error) {
		c.Check(fallbackKeyFile, Equals, filepath.Join(dirs.SnapSaveDir, "device/fde", "tpm-policy-auth-key"))
		c.Check(devices, DeepEquals, []string{"/dev/disk/by-uuid/123", "/dev/disk/by-uuid/456"})
		return []byte{1, 2, 3, 4}, nil
	})()

	err := backend.ResealKeyForBootChains(myState, device.SealingMethodTPM, s.rootdir, &boot.ResealKeyForBootChainsParams{BootChains: bootChains})
	c.Assert(err, IsNil)
	c.Assert(resealKeysCalls, Equals, 3)

	// verify the boot chains data file for run key
	runPbc, cnt, err := boot.ReadBootChains(filepath.Join(dirs.SnapFDEDir, "boot-chains"))
	c.Assert(err, IsNil)
	c.Assert(cnt, Equals, 1)
	c.Check(runPbc, DeepEquals, boot.ToPredictableBootChains(removeKernelBootFiles(append(runBootChains, recoveryBootChainsForRun...))))
	// recovery boot chains
	recoveryPbc, cnt, err := boot.ReadBootChains(filepath.Join(dirs.SnapFDEDir, "recovery-boot-chains"))
	c.Assert(err, IsNil)
	c.Assert(cnt, Equals, 1)
	c.Check(recoveryPbc, DeepEquals, boot.ToPredictableBootChains(removeKernelBootFiles(recoveryBootChains)))
}

func (s *resealTestSuite) testResealKeyForBootchainsWithTryModel(c *C, shimId, grubId string) {
	// mock asset cache
	mockAssetsCache(c, s.rootdir, "grub", []string{
		fmt.Sprintf("%s-shim-hash", shimId),
		fmt.Sprintf("%s-grub-hash", grubId),
		"grubx64.efi-run-grub-hash",
	})

	buildProfileCalls := 0
	restore := backend.MockSecbootBuildPCRProtectionProfile(func(modelParams []*secboot.SealKeyModelParams, allowInsufficientDmaProtection bool) (secboot.SerializedPCRProfile, error) {
		buildProfileCalls++

		c.Check(allowInsufficientDmaProtection, Equals, true)

		switch buildProfileCalls {
		case 1: // run key
			// 2 models, one current and one try model
			c.Assert(modelParams, HasLen, 2)
			// shared parameters
			c.Assert(modelParams[0].Model.Model(), Equals, "my-model-uc20")
			c.Assert(modelParams[0].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=factory-reset snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
			})
			// 2 load chains (bootloader + run kernel, bootloader + recovery kernel)
			c.Assert(modelParams[0].EFILoadChains, HasLen, 2)

			c.Assert(modelParams[1].Model.Model(), Equals, "try-my-model-uc20")
			c.Assert(modelParams[1].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=factory-reset snapd_recovery_system=1234 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=1234 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
			})
			// 2 load chains (bootloader + run kernel, bootloader + recovery kernel)
			c.Assert(modelParams[1].EFILoadChains, HasLen, 2)
		case 2: // run only key
			// 2 models, current and try
			c.Assert(modelParams, HasLen, 2)
			// shared parameters
			c.Assert(modelParams[0].Model.Model(), Equals, "my-model-uc20")
			c.Assert(modelParams[0].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
			})
			c.Assert(modelParams[0].EFILoadChains, HasLen, 1)

			c.Assert(modelParams[1].Model.Model(), Equals, "try-my-model-uc20")
			c.Assert(modelParams[1].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
			})
			c.Assert(modelParams[1].EFILoadChains, HasLen, 1)
		case 3: // recovery keys
			// only the current model
			c.Assert(modelParams, HasLen, 1)
			// shared parameters
			c.Assert(modelParams[0].Model.Model(), Equals, "my-model-uc20")
			for _, mp := range modelParams {
				c.Assert(mp.KernelCmdlines, DeepEquals, []string{
					"snapd_recovery_mode=factory-reset snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
					"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				})
				// load chains
				c.Assert(mp.EFILoadChains, HasLen, 1)
			}
		default:
			c.Errorf("unexpected additional call to secboot.BuildPCRProtectionProfile (call # %d)", buildProfileCalls)
		}

		// recovery parameters
		shim := bootloader.NewBootFile("", filepath.Join(s.rootdir, fmt.Sprintf("var/lib/snapd/boot-assets/grub/%s-shim-hash", shimId)), bootloader.RoleRecovery)
		grub := bootloader.NewBootFile("", filepath.Join(s.rootdir, fmt.Sprintf("var/lib/snapd/boot-assets/grub/%s-grub-hash", grubId)), bootloader.RoleRecovery)
		kernelOldRecovery := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)
		// kernel from a tried recovery system
		kernelNewRecovery := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_999.snap", "kernel.efi", bootloader.RoleRecovery)
		// run mode parameters
		runGrub := bootloader.NewBootFile("", filepath.Join(s.rootdir, "var/lib/snapd/boot-assets/grub/grubx64.efi-run-grub-hash"), bootloader.RoleRunMode)
		runKernel := bootloader.NewBootFile(filepath.Join(s.rootdir, "var/lib/snapd/snaps/pc-kernel_500.snap"), "kernel.efi", bootloader.RoleRunMode)

		// verify the load chains, which  are identical for both models
		switch buildProfileCalls {
		case 1: // run load chain for 2 models, current and a try model
			c.Assert(modelParams, HasLen, 2)
			// each load chain has either the run kernel (shared for
			// both), or the kernel of the respective recovery
			// system
			c.Assert(modelParams[0].EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(kernelOldRecovery),
					)),
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(runGrub,
							secboot.NewLoadChain(runKernel)),
					)),
			})
			c.Assert(modelParams[1].EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(kernelNewRecovery),
					)),
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(runGrub,
							secboot.NewLoadChain(runKernel)),
					)),
			})
		case 2: // run only load chain for 2 models, current and a try model
			c.Assert(modelParams, HasLen, 2)
			c.Assert(modelParams[0].EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(runGrub,
							secboot.NewLoadChain(runKernel)),
					)),
			})
			c.Assert(modelParams[1].EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(runGrub,
							secboot.NewLoadChain(runKernel)),
					)),
			})
		case 3: // recovery load chains, only for the current model
			c.Assert(modelParams, HasLen, 1)
			// load chain with a kernel from a recovery system that
			// matches the current model only
			c.Assert(modelParams[0].EFILoadChains, DeepEquals, []*secboot.LoadChain{
				secboot.NewLoadChain(shim,
					secboot.NewLoadChain(grub,
						secboot.NewLoadChain(kernelOldRecovery),
					)),
			})
		}

		return []byte(`"serialized-pcr-profile"`), nil
	})
	defer restore()

	// set mock key resealing
	resealKeysCalls := 0
	restore = backend.MockSecbootResealKeys(func(params *secboot.ResealKeysParams, newPCRPolicyVersion bool) (secboot.UpdatedKeys, error) {
		c.Check(params.PrimaryKey, DeepEquals, []byte{1, 2, 3, 4})
		c.Check(newPCRPolicyVersion, Equals, false)

		resealKeysCalls++
		c.Check(params.PCRProfile, DeepEquals, secboot.SerializedPCRProfile(`"serialized-pcr-profile"`))

		switch resealKeysCalls {
		case 1: // run key
			c.Assert(params.Keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/123",
					SlotName:   "default",
					KeyFile:    filepath.Join(boot.InitramfsBootEncryptionKeyDir, "ubuntu-data.sealed-key"),
				},
			})
		case 2: // recovery keys
			c.Assert(params.Keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/123",
					SlotName:   "default-fallback",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
				},
			})
		case 3:
			c.Assert(params.Keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/456",
					SlotName:   "default-fallback",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
				},
			})
		default:
			c.Errorf("unexpected additional call to secboot.ResealKeys (call # %d)", resealKeysCalls)
		}

		return nil, nil
	})
	defer restore()

	recoveryAssetChain := []boot.BootAsset{{
		Role:   "recovery",
		Name:   shimId,
		Hashes: []string{"shim-hash"},
	}, {
		Role:   "recovery",
		Name:   grubId,
		Hashes: []string{"grub-hash"},
	}}
	runAssetChain := []boot.BootAsset{{
		Role:   "recovery",
		Name:   shimId,
		Hashes: []string{"shim-hash"},
	}, {
		Role:   "recovery",
		Name:   grubId,
		Hashes: []string{"grub-hash"},
	}, {
		Role:   "run-mode",
		Name:   "grubx64.efi",
		Hashes: []string{"run-grub-hash"},
	}}

	kernelOldRecovery := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)
	kernelNewRecovery := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_999.snap", "kernel.efi", bootloader.RoleRecovery)
	runKernel := bootloader.NewBootFile(filepath.Join(s.rootdir, "var/lib/snapd/snaps/pc-kernel_500.snap"), "kernel.efi", bootloader.RoleRunMode)

	recoveryBootChainsForRun := []boot.BootChain{
		// the current model
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain:     recoveryAssetChain,
			Kernel:         "pc-kernel",
			KernelRevision: "1",
			KernelCmdlines: []string{
				"snapd_recovery_mode=factory-reset snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
			},
			KernelBootFile: kernelOldRecovery,
		},
		// the try model
		{
			BrandID:        "my-brand",
			Model:          "try-my-model-uc20",
			Grade:          "secured",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain:     recoveryAssetChain,
			Kernel:         "pc-kernel",
			KernelRevision: "999",
			KernelCmdlines: []string{
				"snapd_recovery_mode=factory-reset snapd_recovery_system=1234 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=1234 console=ttyS0 console=tty1 panic=-1",
			},
			KernelBootFile: kernelNewRecovery,
		},
	}

	runBootChains := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain:     runAssetChain,
			Kernel:         "pc-kernel",
			KernelRevision: "500",
			KernelCmdlines: []string{
				"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
			},
			KernelBootFile: runKernel,
		},
		{
			BrandID:        "my-brand",
			Model:          "try-my-model-uc20",
			Grade:          "secured",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain:     runAssetChain,
			Kernel:         "pc-kernel",
			KernelRevision: "500",
			KernelCmdlines: []string{
				"snapd_recovery_mode=run console=ttyS0 console=tty1 panic=-1",
			},
			KernelBootFile: runKernel,
		},
	}

	recoveryBootChains := []boot.BootChain{
		// recovery keys are sealed to current model only
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain:     recoveryAssetChain,
			Kernel:         "pc-kernel",
			KernelRevision: "1",
			KernelCmdlines: []string{
				"snapd_recovery_mode=factory-reset snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 console=ttyS0 console=tty1 panic=-1",
			},
			KernelBootFile: kernelOldRecovery,
		},
	}

	bootChains := boot.BootChains{
		RunModeBootChains:           runBootChains,
		RecoveryBootChainsForRunKey: recoveryBootChainsForRun,
		RecoveryBootChains:          recoveryBootChains,
		RoleToBlName: map[bootloader.Role]string{
			bootloader.RoleRunMode:  "grub",
			bootloader.RoleRecovery: "grub",
		},
	}

	myState := &fakeState{}
	myState.EncryptedContainers = []backend.EncryptedContainer{
		&encryptedContainer{
			uuid:          "123",
			containerRole: "system-data",
			legacyKeys: map[string]string{
				"default":          filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
			},
		},
		&encryptedContainer{
			uuid:          "456",
			containerRole: "system-save",
			legacyKeys: map[string]string{
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
			},
		},
	}

	defer backend.MockSecbootGetPrimaryKey(func(devices []string, fallbackKeyFile string) ([]byte, error) {
		c.Check(fallbackKeyFile, Equals, filepath.Join(dirs.SnapSaveDir, "device/fde", "tpm-policy-auth-key"))
		c.Check(devices, DeepEquals, []string{"/dev/disk/by-uuid/123", "/dev/disk/by-uuid/456"})
		return []byte{1, 2, 3, 4}, nil
	})()

	err := backend.ResealKeyForBootChains(myState, device.SealingMethodTPM, s.rootdir, &boot.ResealKeyForBootChainsParams{BootChains: bootChains})
	c.Assert(err, IsNil)
	c.Assert(resealKeysCalls, Equals, 3)

	// verify the boot chains data file for run key
	runPbc, cnt, err := boot.ReadBootChains(filepath.Join(dirs.SnapFDEDir, "boot-chains"))
	c.Assert(err, IsNil)
	c.Assert(cnt, Equals, 1)
	c.Check(runPbc, DeepEquals, boot.ToPredictableBootChains(removeKernelBootFiles(append(runBootChains, recoveryBootChainsForRun...))))
	// recovery boot chains
	recoveryPbc, cnt, err := boot.ReadBootChains(filepath.Join(dirs.SnapFDEDir, "recovery-boot-chains"))
	c.Assert(err, IsNil)
	c.Assert(cnt, Equals, 1)
	c.Check(recoveryPbc, DeepEquals, boot.ToPredictableBootChains(removeKernelBootFiles(recoveryBootChains)))
}

func (s *resealTestSuite) TestResealKeyForBootchainsWithTryModelOldBootChain(c *C) {
	s.testResealKeyForBootchainsWithTryModel(c, "bootx64.efi", "grubx64.efi")
}

func (s *resealTestSuite) TestResealKeyForBootchainsWithTryModelNewBootChain(c *C) {
	s.testResealKeyForBootchainsWithTryModel(c, "ubuntu:shimx64.efi", "ubuntu:grubx64.efi")
}

func (s *resealTestSuite) TestResealKeyForBootchainsFallbackCmdline(c *C) {
	err := boot.WriteBootChains(nil, filepath.Join(dirs.SnapFDEDir, "boot-chains"), 9)
	c.Assert(err, IsNil)
	// mock asset cache
	mockAssetsCache(c, s.rootdir, "trusted", []string{
		"asset-asset-hash-1",
	})

	// match one of current kernels
	runKernelBf := bootloader.NewBootFile("/var/lib/snapd/snap/pc-kernel_500.snap", "kernel.efi", bootloader.RoleRunMode)
	// match the seed kernel
	recoveryKernelBf := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)

	bootdir := c.MkDir()
	mtbl := bootloadertest.Mock("trusted", bootdir).WithTrustedAssets()
	mtbl.TrustedAssetsMap = map[string]string{"asset": "asset"}
	mtbl.StaticCommandLine = "static cmdline"
	mtbl.BootChainList = []bootloader.BootFile{
		bootloader.NewBootFile("", "asset", bootloader.RoleRunMode),
		runKernelBf,
	}
	mtbl.RecoveryBootChainList = []bootloader.BootFile{
		bootloader.NewBootFile("", "asset", bootloader.RoleRecovery),
		recoveryKernelBf,
	}
	bootloader.Force(mtbl)
	defer bootloader.Force(nil)

	buildProfileCalls := 0
	restore := backend.MockSecbootBuildPCRProtectionProfile(func(modelParams []*secboot.SealKeyModelParams, allowInsufficientDmaProtection bool) (secboot.SerializedPCRProfile, error) {
		buildProfileCalls++

		c.Check(allowInsufficientDmaProtection, Equals, true)

		c.Assert(modelParams, HasLen, 1)

		switch buildProfileCalls {
		case 1:
			c.Assert(modelParams[0].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 static cmdline",
				"snapd_recovery_mode=run static cmdline",
			})
		case 2:
			c.Assert(modelParams[0].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=run static cmdline",
			})
		case 3:
			c.Assert(modelParams[0].KernelCmdlines, DeepEquals, []string{
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 static cmdline",
			})
		default:
			c.Fatalf("unexpected number of build profile calls, %v", modelParams)
		}

		return []byte(`"serialized-pcr-profile"`), nil
	})
	defer restore()

	// set mock key resealing
	resealKeysCalls := 0
	restore = backend.MockSecbootResealKeys(func(params *secboot.ResealKeysParams, newPCRPolicyVersion bool) (secboot.UpdatedKeys, error) {
		resealKeysCalls++

		c.Check(newPCRPolicyVersion, Equals, false)
		c.Check(params.PCRProfile, DeepEquals, secboot.SerializedPCRProfile(`"serialized-pcr-profile"`))
		c.Logf("reseal: %+v", params)
		switch resealKeysCalls {
		case 1:
		case 2:
		case 3:
		default:
			c.Fatalf("unexpected number of reseal calls, %v", params)
		}
		return nil, nil
	})
	defer restore()

	runBootChains := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   "run-mode",
					Name:   "asset",
					Hashes: []string{"asset-hash-1"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "500",
			KernelCmdlines: []string{
				"snapd_recovery_mode=run static cmdline",
			},
			KernelBootFile: runKernelBf,
		},
	}

	recoveryBootChainsForRun := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   "recovery",
					Name:   "asset",
					Hashes: []string{"asset-hash-1"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "1",
			KernelCmdlines: []string{
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 static cmdline",
			},
			KernelBootFile: recoveryKernelBf,
		},
	}

	recoveryBootChains := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   "recovery",
					Name:   "asset",
					Hashes: []string{"asset-hash-1"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "1",
			KernelCmdlines: []string{
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 static cmdline",
			},
			KernelBootFile: recoveryKernelBf,
		},
	}

	bootChains := boot.BootChains{
		RunModeBootChains:           runBootChains,
		RecoveryBootChainsForRunKey: recoveryBootChainsForRun,
		RecoveryBootChains:          recoveryBootChains,
		RoleToBlName: map[bootloader.Role]string{
			bootloader.RoleRunMode:  "trusted",
			bootloader.RoleRecovery: "trusted",
		},
	}

	myState := &fakeState{}
	myState.EncryptedContainers = []backend.EncryptedContainer{
		&encryptedContainer{
			uuid:          "123",
			containerRole: "system-data",
			legacyKeys: map[string]string{
				"default":          filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
			},
		},
		&encryptedContainer{
			uuid:          "456",
			containerRole: "system-save",
			legacyKeys: map[string]string{
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
			},
		},
	}

	defer backend.MockSecbootGetPrimaryKey(func(devices []string, fallbackKeyFile string) ([]byte, error) {
		c.Check(fallbackKeyFile, Equals, filepath.Join(dirs.SnapSaveDir, "device/fde", "tpm-policy-auth-key"))
		c.Check(devices, DeepEquals, []string{"/dev/disk/by-uuid/123", "/dev/disk/by-uuid/456"})
		return []byte{1, 2, 3, 4}, nil
	})()

	err = backend.ResealKeyForBootChains(myState, device.SealingMethodTPM, s.rootdir, &boot.ResealKeyForBootChainsParams{BootChains: bootChains})
	c.Assert(err, IsNil)
	c.Assert(resealKeysCalls, Equals, 3)

	// verify the boot chains data file
	pbc, cnt, err := boot.ReadBootChains(filepath.Join(dirs.SnapFDEDir, "boot-chains"))
	c.Assert(err, IsNil)
	c.Assert(cnt, Equals, 10)
	c.Check(pbc, DeepEquals, boot.ToPredictableBootChains(removeKernelBootFiles(append(runBootChains, recoveryBootChainsForRun...))))
}

func (s *resealTestSuite) TestHooksResealHappy(c *C) {
	model := boottest.MakeMockUC20Model()
	bootChains := boot.BootChains{
		RunModeBootChains: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),
				KernelCmdlines: []string{
					"mode=run",
				},
			},
		},

		RecoveryBootChainsForRunKey: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),
				KernelCmdlines: []string{
					"mode=recover",
				},
			},
		},

		RecoveryBootChains: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),
				KernelCmdlines: []string{
					"mode=recover",
				},
			},
		},
	}

	resealCalls := 0
	restore := backend.MockSecbootResealKeysWithFDESetupHook(func(keys []secboot.KeyDataLocation, primaryKeyGetter func() ([]byte, error), models []secboot.ModelForSealing, bootModes []string) error {
		resealCalls++

		primaryKey, err := primaryKeyGetter()
		c.Assert(err, IsNil)
		switch resealCalls {
		case 1:
			// Resealing the run+recover key for data partition
			c.Check(keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/123",
					SlotName:   "default",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				},
			})
			c.Check(primaryKey, DeepEquals, []byte{1, 2, 3, 4})
			c.Assert(models, HasLen, 1)
			c.Check(models[0].Model(), Equals, model.Model())
			c.Check(bootModes, DeepEquals, []string{"run", "recover"})
		case 2:
			// Resealing the recovery key for both data partition
			c.Check(keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/123",
					SlotName:   "default-fallback",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
				},
			})
			c.Check(primaryKey, DeepEquals, []byte{1, 2, 3, 4})
			c.Assert(models, HasLen, 1)
			c.Check(models[0].Model(), Equals, model.Model())
			c.Check(bootModes, DeepEquals, []string{"recover"})
		case 3:
			// Resealing the recovery key for both save partition
			c.Check(keys, DeepEquals, []secboot.KeyDataLocation{
				{
					DevicePath: "/dev/disk/by-uuid/456",
					SlotName:   "default-fallback",
					KeyFile:    filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
				},
			})
			c.Check(primaryKey, DeepEquals, []byte{1, 2, 3, 4})
			c.Assert(models, HasLen, 1)
			c.Check(models[0].Model(), Equals, model.Model())
			c.Check(bootModes, DeepEquals, []string{"recover", "factory-reset"})
		default:
			c.Errorf("unexpected additional call to secboot.ResealKey (call # %d)", resealCalls)
		}
		return nil
	})

	defer restore()

	myState := &fakeState{}
	myState.EncryptedContainers = []backend.EncryptedContainer{
		&encryptedContainer{
			uuid:          "123",
			containerRole: "system-data",
			legacyKeys: map[string]string{
				"default":          filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
			},
		},
		&encryptedContainer{
			uuid:          "456",
			containerRole: "system-save",
			legacyKeys: map[string]string{
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
			},
		},
	}

	defer backend.MockSecbootGetPrimaryKey(func(devices []string, fallbackKeyFile string) ([]byte, error) {
		c.Check(fallbackKeyFile, Equals, filepath.Join(s.rootdir, "run/mnt/ubuntu-save/device/fde/aux-key"))
		c.Check(devices, DeepEquals, []string{"/dev/disk/by-uuid/123", "/dev/disk/by-uuid/456"})
		return []byte{1, 2, 3, 4}, nil
	})()

	err := backend.ResealKeyForBootChains(myState, device.SealingMethodFDESetupHook, s.rootdir, &boot.ResealKeyForBootChainsParams{BootChains: bootChains})
	c.Assert(err, IsNil)

	c.Check(resealCalls, Equals, 3)
}

func (s *resealTestSuite) TestHooksResealIgnoreFDEHooks(c *C) {
	model := boottest.MakeMockUC20Model()
	bootChains := boot.BootChains{
		RunModeBootChains: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),
				KernelCmdlines: []string{
					"mode=run",
				},
			},
		},

		RecoveryBootChainsForRunKey: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),
				KernelCmdlines: []string{
					"mode=recover",
				},
			},
		},

		RecoveryBootChains: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),
				KernelCmdlines: []string{
					"mode=recover",
				},
			},
		},
	}

	defer backend.MockSecbootResealKeysWithFDESetupHook(func(keys []secboot.KeyDataLocation, primaryKeyGetter func() ([]byte, error), models []secboot.ModelForSealing, bootModes []string) error {
		c.Errorf("unexpected call")
		return fmt.Errorf("unexpected call")
	})()

	myState := &fakeState{}
	myState.EncryptedContainers = []backend.EncryptedContainer{
		&encryptedContainer{
			uuid:          "123",
			containerRole: "system-data",
			legacyKeys: map[string]string{
				"default":          filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
			},
		},
		&encryptedContainer{
			uuid:          "456",
			containerRole: "system-save",
			legacyKeys: map[string]string{
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
			},
		},
	}

	defer backend.MockSecbootGetPrimaryKey(func(devices []string, fallbackKeyFile string) ([]byte, error) {
		c.Errorf("unexpected call")
		return nil, fmt.Errorf("unexpected call")
	})()

	opts := boot.ResealKeyToModeenvOptions{IgnoreFDEHooks: true}
	err := backend.ResealKeyForBootChains(myState, device.SealingMethodFDESetupHook, s.rootdir, &boot.ResealKeyForBootChainsParams{BootChains: bootChains, Options: opts})
	c.Assert(err, IsNil)
}

func (s *resealTestSuite) TestResealKeyForSignatureDBUpdate(c *C) {
	mockAssetsCache(c, s.rootdir, "trusted", []string{
		"asset-asset-hash-1",
	})

	// match one of current kernels
	runKernelBf := bootloader.NewBootFile("/var/lib/snapd/snap/pc-kernel_500.snap", "kernel.efi", bootloader.RoleRunMode)
	// match the seed kernel
	recoveryKernelBf := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)

	// keep this relatively realistic
	runBootChains := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   "run-mode",
					Name:   "asset",
					Hashes: []string{"asset-hash-1"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "500",
			KernelCmdlines: []string{
				"snapd_recovery_mode=run static cmdline",
			},
			KernelBootFile: runKernelBf,
		},
	}

	recoveryBootChainsForRun := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   "recovery",
					Name:   "asset",
					Hashes: []string{"asset-hash-1"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "1",
			KernelCmdlines: []string{
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 static cmdline",
			},
			KernelBootFile: recoveryKernelBf,
		},
	}

	recoveryBootChains := []boot.BootChain{
		{
			BrandID:        "my-brand",
			Model:          "my-model-uc20",
			Grade:          "dangerous",
			ModelSignKeyID: "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij",
			AssetChain: []boot.BootAsset{
				{
					Role:   "recovery",
					Name:   "asset",
					Hashes: []string{"asset-hash-1"},
				},
			},
			Kernel:         "pc-kernel",
			KernelRevision: "1",
			KernelCmdlines: []string{
				"snapd_recovery_mode=recover snapd_recovery_system=20200825 static cmdline",
			},
			KernelBootFile: recoveryKernelBf,
		},
	}

	// write boot chains so that a usual reseal would not happen
	pbc := boot.ToPredictableBootChains(append(runBootChains, recoveryBootChainsForRun...))
	err := boot.WriteBootChains(pbc, backend.BootChainsFileUnder(dirs.GlobalRootDir), 0)
	c.Assert(err, IsNil)

	rpbc := boot.ToPredictableBootChains(recoveryBootChains)
	err = boot.WriteBootChains(rpbc, backend.RecoveryBootChainsFileUnder(dirs.GlobalRootDir), 0)
	c.Assert(err, IsNil)

	// make sure that normally a reseal would not be needed
	const expectReseal = true
	needed, next, err := boot.IsResealNeeded(pbc, backend.BootChainsFileUnder(dirs.GlobalRootDir), expectReseal)
	c.Assert(err, IsNil)
	c.Assert(needed, Equals, false)
	c.Assert(next, Equals, 1)
	// and same for recovery
	needed, next, err = boot.IsResealNeeded(rpbc, backend.RecoveryBootChainsFileUnder(dirs.GlobalRootDir), expectReseal)
	c.Assert(err, IsNil)
	c.Assert(needed, Equals, false)
	c.Assert(next, Equals, 1)

	bootChains := boot.BootChains{
		RunModeBootChains:           runBootChains,
		RecoveryBootChainsForRunKey: recoveryBootChainsForRun,
		RecoveryBootChains:          recoveryBootChains,
		RoleToBlName: map[bootloader.Role]string{
			bootloader.RoleRunMode:  "trusted",
			bootloader.RoleRecovery: "trusted",
		},
	}

	buildProfileCalls := 0
	restore := backend.MockSecbootBuildPCRProtectionProfile(func(modelParams []*secboot.SealKeyModelParams, allowInsufficientDmaProtection bool) (secboot.SerializedPCRProfile, error) {
		buildProfileCalls++

		c.Check(allowInsufficientDmaProtection, Equals, true)

		c.Assert(modelParams, HasLen, 1)
		// same DBX update paylad is included for both run and recovery keys
		c.Assert(modelParams[0].EFISignatureDbxUpdate, DeepEquals, []byte("dbx-payload"))

		return []byte(`"serialized-pcr-profile-with-dbx"`), nil
	})
	defer restore()

	// set mock key resealing
	resealKeysCalls := 0
	restore = backend.MockSecbootResealKeys(func(params *secboot.ResealKeysParams, newPCRPolicyVersion bool) (secboot.UpdatedKeys, error) {
		resealKeysCalls++

		c.Check(newPCRPolicyVersion, Equals, false)
		c.Check(params.PCRProfile, DeepEquals, secboot.SerializedPCRProfile(`"serialized-pcr-profile-with-dbx"`))
		c.Logf("reseal: %+v", params)

		return nil, nil
	})
	defer restore()

	myState := &fakeState{}
	myState.EncryptedContainers = []backend.EncryptedContainer{
		&encryptedContainer{
			uuid:          "123",
			containerRole: "system-data",
			legacyKeys: map[string]string{
				"default":          filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
			},
		},
		&encryptedContainer{
			uuid:          "456",
			containerRole: "system-save",
			legacyKeys: map[string]string{
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
			},
		},
	}

	defer backend.MockSecbootGetPrimaryKey(func(devices []string, fallbackKeyFile string) ([]byte, error) {
		c.Check(fallbackKeyFile, Equals, filepath.Join(dirs.SnapSaveDir, "device/fde", "tpm-policy-auth-key"))
		c.Check(devices, DeepEquals, []string{"/dev/disk/by-uuid/123", "/dev/disk/by-uuid/456"})
		return []byte{1, 2, 3, 4}, nil
	})()

	err = backend.ResealKeysForSignaturesDBUpdate(myState, device.SealingMethodTPM, dirs.GlobalRootDir,
		&boot.ResealKeyForBootChainsParams{BootChains: bootChains}, []byte("dbx-payload"))
	c.Assert(err, IsNil)

	// reseal was called
	c.Check(buildProfileCalls, Equals, 3)
	c.Check(resealKeysCalls, Equals, 3)
}

func (s *resealTestSuite) TestTPMResealEnsureProvisioned(c *C) {
	bl := bootloadertest.Mock("trusted", "").WithTrustedAssets()
	bootloader.Force(bl)
	defer bootloader.Force(nil)

	bl.TrustedAssetsMap = map[string]string{
		"asset": "asset",
	}
	recoveryKernel := bootloader.NewBootFile("/var/lib/snapd/seed/snaps/pc-kernel_1.snap", "kernel.efi", bootloader.RoleRecovery)
	runKernel := bootloader.NewBootFile(filepath.Join(s.rootdir, "var/lib/snapd/snaps/pc-kernel_500.snap"), "kernel.efi", bootloader.RoleRunMode)

	bl.RecoveryBootChainList = []bootloader.BootFile{
		bootloader.NewBootFile("", "asset", bootloader.RoleRecovery),
		recoveryKernel,
	}
	bl.BootChainList = []bootloader.BootFile{
		bootloader.NewBootFile("", "asset", bootloader.RoleRunMode),
		runKernel,
	}

	c.Assert(os.MkdirAll(filepath.Join(dirs.SnapBootAssetsDir, "trusted"), 0755), IsNil)
	for _, name := range []string{
		"asset-runassethash",
		"asset-assethash",
	} {
		err := os.WriteFile(filepath.Join(dirs.SnapBootAssetsDir, "trusted", name), nil, 0644)
		c.Assert(err, IsNil)
	}

	model := boottest.MakeMockUC20Model()
	bootChains := boot.BootChains{
		RunModeBootChains: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),

				AssetChain: []boot.BootAsset{
					{
						Role: bootloader.RoleRecovery,
						Name: "asset",
						Hashes: []string{
							"assethash",
						},
					},
					{
						Role: bootloader.RoleRunMode,
						Name: "asset",
						Hashes: []string{
							"runassethash",
						},
					},
				},

				Kernel:         "kernel.efi",
				KernelRevision: "500",
				KernelCmdlines: []string{
					"mode=run",
				},
				KernelBootFile: runKernel,
			},
		},

		RecoveryBootChainsForRunKey: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),

				AssetChain: []boot.BootAsset{
					{
						Role: bootloader.RoleRecovery,
						Name: "asset",
						Hashes: []string{
							"assethash",
						},
					},
				},

				Kernel:         "kernel.efi",
				KernelRevision: "1",
				KernelCmdlines: []string{
					"mode=recover",
				},
				KernelBootFile: recoveryKernel,
			},
		},

		RecoveryBootChains: []boot.BootChain{
			{
				BrandID:        model.BrandID(),
				Model:          model.Model(),
				Classic:        model.Classic(),
				Grade:          model.Grade(),
				ModelSignKeyID: model.SignKeyID(),

				AssetChain: []boot.BootAsset{
					{
						Role: bootloader.RoleRecovery,
						Name: "asset",
						Hashes: []string{
							"assethash",
						},
					},
				},

				Kernel:         "kernel.efi",
				KernelRevision: "1",
				KernelCmdlines: []string{
					"mode=recover",
				},
				KernelBootFile: recoveryKernel,
			},
		},

		RoleToBlName: map[bootloader.Role]string{
			bootloader.RoleRecovery: "trusted",
			bootloader.RoleRunMode:  "trusted",
		},
	}

	defer backend.MockSecbootBuildPCRProtectionProfile(func(modelParams []*secboot.SealKeyModelParams, allowInsufficientDmaProtection bool) (secboot.SerializedPCRProfile, error) {
		return []byte(`"serialized-pcr-profile"`), nil
	})()

	resealCalls := 0
	defer backend.MockSecbootResealKeys(func(params *secboot.ResealKeysParams, newPCRPolicyVersion bool) (secboot.UpdatedKeys, error) {
		resealCalls++
		return nil, nil
	})()

	myState := &fakeState{}
	myState.EncryptedContainers = []backend.EncryptedContainer{
		&encryptedContainer{
			uuid:          "123",
			containerRole: "system-data",
			legacyKeys: map[string]string{
				"default":          filepath.Join(s.rootdir, "run/mnt/ubuntu-boot/device/fde/ubuntu-data.sealed-key"),
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-data.recovery.sealed-key"),
			},
		},
		&encryptedContainer{
			uuid:          "456",
			containerRole: "system-save",
			legacyKeys: map[string]string{
				"default-fallback": filepath.Join(s.rootdir, "run/mnt/ubuntu-seed/device/fde/ubuntu-save.recovery.sealed-key"),
			},
		},
	}

	defer backend.MockSecbootGetPrimaryKey(func(devices []string, fallbackKeyFile string) ([]byte, error) {
		return []byte{1, 2, 3, 4}, nil
	})()

	provisioned := 0
	defer backend.MockSecbootProvisionTPM(func(mode secboot.TPMProvisionMode, lockoutAuthFile string) error {
		provisioned++
		c.Check(mode, Equals, secboot.TPMPartialReprovision)
		c.Check(lockoutAuthFile, Equals, filepath.Join(s.rootdir, "/run/mnt/ubuntu-save/device/fde/tpm-lockout-auth"))
		return nil
	})()

	opts := boot.ResealKeyToModeenvOptions{ExpectReseal: true, EnsureProvisioned: true}
	err := backend.ResealKeyForBootChains(myState, device.SealingMethodTPM, s.rootdir, &boot.ResealKeyForBootChainsParams{BootChains: bootChains, Options: opts})
	c.Assert(err, IsNil)

	c.Check(resealCalls, Equals, 3)
	c.Check(provisioned, Equals, 1)
}
