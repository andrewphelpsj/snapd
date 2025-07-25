// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017 Canonical Ltd
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

package interfaces_test

import (
	"errors"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/interfaces"
	"github.com/snapcore/snapd/interfaces/ifacetest"
	"github.com/snapcore/snapd/interfaces/utils"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/testutil"
)

type connSuite struct {
	testutil.BaseTest
	plug       *snap.PlugInfo
	plugAppSet *interfaces.SnapAppSet
	slot       *snap.SlotInfo
	slotAppSet *interfaces.SnapAppSet
}

var _ = Suite(&connSuite{})

func (s *connSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)

	dirs.SetRootDir(c.MkDir())
	s.AddCleanup(func() { dirs.SetRootDir("") })

	s.BaseTest.AddCleanup(snap.MockSanitizePlugsSlots(func(snapInfo *snap.Info) {}))
	s.plugAppSet = ifacetest.MockInfoAndAppSet(c, `
name: consumer
version: 0
apps:
    app:
plugs:
    plug:
        interface: interface
        attr: value
        complex:
            c: d
`, nil, nil)
	s.plug = s.plugAppSet.Info().Plugs["plug"]
	s.slotAppSet = ifacetest.MockInfoAndAppSet(c, `
name: producer
version: 0
apps:
    app:
slots:
    slot:
        interface: interface
        attr: value
        number: 100
        complex:
            a: b
`, nil, nil)
	s.slot = s.slotAppSet.Info().Slots["slot"]
}

func (s *connSuite) TearDownTest(c *C) {
	s.BaseTest.TearDownTest(c)
}

// Make sure ConnectedPlug,ConnectedSlot, PlugInfo, SlotInfo implement Attrer.
var _ interfaces.Attrer = (*interfaces.ConnectedPlug)(nil)
var _ interfaces.Attrer = (*interfaces.ConnectedSlot)(nil)
var _ interfaces.Attrer = (*snap.PlugInfo)(nil)
var _ interfaces.Attrer = (*snap.SlotInfo)(nil)

func (s *connSuite) TestStaticSlotAttrs(c *C) {
	slot := interfaces.NewConnectedSlot(s.slot, s.slotAppSet, nil, nil)
	c.Assert(slot, NotNil)

	var val string
	var intVal int
	c.Assert(slot.StaticAttr("unknown", &val), ErrorMatches, `snap "producer" does not have attribute "unknown" for interface "interface"`)

	attrs := slot.StaticAttrs()
	c.Assert(attrs, DeepEquals, map[string]any{
		"attr":    "value",
		"number":  int64(100),
		"complex": map[string]any{"a": "b"},
	})
	slot.StaticAttr("attr", &val)
	c.Assert(val, Equals, "value")

	c.Assert(slot.StaticAttr("unknown", &val), ErrorMatches, `snap "producer" does not have attribute "unknown" for interface "interface"`)
	c.Check(slot.StaticAttr("attr", &intVal), ErrorMatches, `snap "producer" has interface "interface" with invalid value type string for "attr" attribute: \*int`)
	c.Check(slot.StaticAttr("attr", val), ErrorMatches, `internal error: cannot get "attr" attribute of interface "interface" with non-pointer value`)

	// static attributes passed via args take precedence over slot.Attrs
	slot2 := interfaces.NewConnectedSlot(s.slot, s.slotAppSet, map[string]any{"foo": "bar"}, nil)
	slot2.StaticAttr("foo", &val)
	c.Assert(val, Equals, "bar")
}

func (s *connSuite) TestSlotRef(c *C) {
	slot := interfaces.NewConnectedSlot(s.slot, s.slotAppSet, nil, nil)
	c.Assert(slot, NotNil)
	c.Assert(*slot.Ref(), DeepEquals, interfaces.SlotRef{Snap: "producer", Name: "slot"})
}

func (s *connSuite) TestPlugRef(c *C) {
	plug := interfaces.NewConnectedPlug(s.plug, s.plugAppSet, nil, nil)
	c.Assert(plug, NotNil)
	c.Assert(*plug.Ref(), DeepEquals, interfaces.PlugRef{Snap: "consumer", Name: "plug"})
}

func (s *connSuite) TestStaticPlugAttrs(c *C) {
	plug := interfaces.NewConnectedPlug(s.plug, s.plugAppSet, nil, nil)
	c.Assert(plug, NotNil)

	var val string
	var intVal int
	c.Assert(plug.StaticAttr("unknown", &val), ErrorMatches, `snap "consumer" does not have attribute "unknown" for interface "interface"`)

	attrs := plug.StaticAttrs()
	c.Assert(attrs, DeepEquals, map[string]any{
		"attr":    "value",
		"complex": map[string]any{"c": "d"},
	})
	plug.StaticAttr("attr", &val)
	c.Assert(val, Equals, "value")

	c.Assert(plug.StaticAttr("unknown", &val), ErrorMatches, `snap "consumer" does not have attribute "unknown" for interface "interface"`)
	c.Check(plug.StaticAttr("attr", &intVal), ErrorMatches, `snap "consumer" has interface "interface" with invalid value type string for "attr" attribute: \*int`)
	c.Check(plug.StaticAttr("attr", val), ErrorMatches, `internal error: cannot get "attr" attribute of interface "interface" with non-pointer value`)

	// static attributes passed via args take precedence over plug.Attrs
	plug2 := interfaces.NewConnectedPlug(s.plug, s.plugAppSet, map[string]any{"foo": "bar"}, nil)
	plug2.StaticAttr("foo", &val)
	c.Assert(val, Equals, "bar")
}

func (s *connSuite) TestDynamicSlotAttrs(c *C) {
	attrs := map[string]any{
		"foo":    "bar",
		"number": int(100),
	}
	slot := interfaces.NewConnectedSlot(s.slot, s.slotAppSet, nil, attrs)
	c.Assert(slot, NotNil)

	var strVal string
	var intVal int64
	var mapVal map[string]any

	c.Assert(slot.Attr("foo", &strVal), IsNil)
	c.Assert(strVal, Equals, "bar")

	c.Assert(slot.Attr("attr", &strVal), IsNil)
	c.Assert(strVal, Equals, "value")

	c.Assert(slot.Attr("number", &intVal), IsNil)
	c.Assert(intVal, Equals, int64(100))

	err := slot.SetAttr("other", map[string]any{"number-two": int(222)})
	c.Assert(err, IsNil)
	c.Assert(slot.Attr("other", &mapVal), IsNil)
	num := mapVal["number-two"]
	c.Assert(num, Equals, int64(222))

	c.Check(slot.Attr("unknown", &strVal), ErrorMatches, `snap "producer" does not have attribute "unknown" for interface "interface"`)
	c.Check(slot.Attr("foo", &intVal), ErrorMatches, `snap "producer" has interface "interface" with invalid value type string for "foo" attribute: \*int64`)
	c.Check(slot.Attr("number", intVal), ErrorMatches, `internal error: cannot get "number" attribute of interface "interface" with non-pointer value`)
}

func (s *connSuite) TestDottedPathSlot(c *C) {
	attrs := map[string]any{
		"nested": map[string]any{
			"foo": "bar",
		},
	}
	var strVal string

	slot := interfaces.NewConnectedSlot(s.slot, s.slotAppSet, nil, attrs)
	c.Assert(slot, NotNil)

	// static attribute complex.a
	c.Assert(slot.Attr("complex.a", &strVal), IsNil)
	c.Assert(strVal, Equals, "b")

	v, ok := slot.Lookup("complex.a")
	c.Assert(ok, Equals, true)
	c.Assert(v, Equals, "b")

	// dynamic attribute nested.foo
	c.Assert(slot.Attr("nested.foo", &strVal), IsNil)
	c.Assert(strVal, Equals, "bar")

	v, ok = slot.Lookup("nested.foo")
	c.Assert(ok, Equals, true)
	c.Assert(v, Equals, "bar")

	_, ok = slot.Lookup("..")
	c.Assert(ok, Equals, false)
}

func (s *connSuite) TestDottedPathPlug(c *C) {
	attrs := map[string]any{
		"a": "b",
		"nested": map[string]any{
			"foo": "bar",
		},
	}
	var strVal string

	plug := interfaces.NewConnectedPlug(s.plug, s.plugAppSet, nil, attrs)
	c.Assert(plug, NotNil)

	v, ok := plug.Lookup("a")
	c.Assert(ok, Equals, true)
	c.Assert(v, Equals, "b")

	// static attribute complex.c
	c.Assert(plug.Attr("complex.c", &strVal), IsNil)
	c.Assert(strVal, Equals, "d")

	v, ok = plug.Lookup("complex.c")
	c.Assert(ok, Equals, true)
	c.Assert(v, Equals, "d")

	// dynamic attribute nested.foo
	c.Assert(plug.Attr("nested.foo", &strVal), IsNil)
	c.Assert(strVal, Equals, "bar")

	v, ok = plug.Lookup("nested.foo")
	c.Assert(ok, Equals, true)
	c.Assert(v, Equals, "bar")

	_, ok = plug.Lookup("nested.x")
	c.Assert(ok, Equals, false)

	_, ok = plug.Lookup("nested.foo.y")
	c.Assert(ok, Equals, false)

	_, ok = plug.Lookup("..")
	c.Assert(ok, Equals, false)
}

func (s *connSuite) TestLookupFailure(c *C) {
	attrs := map[string]any{}

	slot := interfaces.NewConnectedSlot(s.slot, s.slotAppSet, nil, attrs)
	c.Assert(slot, NotNil)
	plug := interfaces.NewConnectedPlug(s.plug, s.plugAppSet, nil, attrs)
	c.Assert(plug, NotNil)

	v, ok := slot.Lookup("a")
	c.Assert(ok, Equals, false)
	c.Assert(v, IsNil)

	v, ok = plug.Lookup("a")
	c.Assert(ok, Equals, false)
	c.Assert(v, IsNil)
}

func (s *connSuite) TestDynamicPlugAttrs(c *C) {
	attrs := map[string]any{
		"foo":    "bar",
		"number": int(100),
	}
	plug := interfaces.NewConnectedPlug(s.plug, s.plugAppSet, nil, attrs)
	c.Assert(plug, NotNil)

	var strVal string
	var intVal int64
	var mapVal map[string]any

	c.Assert(plug.Attr("foo", &strVal), IsNil)
	c.Assert(strVal, Equals, "bar")

	c.Assert(plug.Attr("attr", &strVal), IsNil)
	c.Assert(strVal, Equals, "value")

	c.Assert(plug.Attr("number", &intVal), IsNil)
	c.Assert(intVal, Equals, int64(100))

	err := plug.SetAttr("other", map[string]any{"number-two": int(222)})
	c.Assert(err, IsNil)
	c.Assert(plug.Attr("other", &mapVal), IsNil)
	num := mapVal["number-two"]
	c.Assert(num, Equals, int64(222))

	c.Check(plug.Attr("unknown", &strVal), ErrorMatches, `snap "consumer" does not have attribute "unknown" for interface "interface"`)
	c.Check(plug.Attr("foo", &intVal), ErrorMatches, `snap "consumer" has interface "interface" with invalid value type string for "foo" attribute: \*int64`)
	c.Check(plug.Attr("number", intVal), ErrorMatches, `internal error: cannot get "number" attribute of interface "interface" with non-pointer value`)
}

func (s *connSuite) TestOverwriteStaticAttrError(c *C) {
	attrs := map[string]any{}

	plug := interfaces.NewConnectedPlug(s.plug, s.plugAppSet, nil, attrs)
	c.Assert(plug, NotNil)
	slot := interfaces.NewConnectedSlot(s.slot, s.slotAppSet, nil, attrs)
	c.Assert(slot, NotNil)

	err := plug.SetAttr("attr", "overwrite")
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, `cannot change attribute "attr" as it was statically specified in the snap details`)

	err = slot.SetAttr("attr", "overwrite")
	c.Assert(err, NotNil)
	c.Assert(err, ErrorMatches, `cannot change attribute "attr" as it was statically specified in the snap details`)
}

func (s *connSuite) TestCopyAttributes(c *C) {
	orig := map[string]any{
		"a": "A",
		"b": true,
		"c": int(100),
		"d": []any{"x", "y", true},
		"e": map[string]any{"e1": "E1"},
	}

	cpy := utils.CopyAttributes(orig)
	c.Check(cpy, DeepEquals, orig)

	cpy["d"].([]any)[0] = 999
	c.Check(orig["d"].([]any)[0], Equals, "x")
	cpy["e"].(map[string]any)["e1"] = "x"
	c.Check(orig["e"].(map[string]any)["e1"], Equals, "E1")
}

func (s *connSuite) TestNewConnectedPlugExplicitStaticAttrs(c *C) {
	staticAttrs := map[string]any{
		"baz": "boom",
	}
	dynAttrs := map[string]any{
		"foo": "bar",
	}
	plug := interfaces.NewConnectedPlug(s.plug, s.plugAppSet, staticAttrs, dynAttrs)
	c.Assert(plug, NotNil)
	c.Assert(plug.StaticAttrs(), DeepEquals, map[string]any{"baz": "boom"})
	c.Assert(plug.DynamicAttrs(), DeepEquals, map[string]any{"foo": "bar"})
}

func (s *connSuite) TestNewConnectedSlotExplicitStaticAttrs(c *C) {
	staticAttrs := map[string]any{
		"baz": "boom",
	}
	dynAttrs := map[string]any{
		"foo": "bar",
	}
	slot := interfaces.NewConnectedSlot(s.slot, s.slotAppSet, staticAttrs, dynAttrs)
	c.Assert(slot, NotNil)
	c.Assert(slot.StaticAttrs(), DeepEquals, map[string]any{"baz": "boom"})
	c.Assert(slot.DynamicAttrs(), DeepEquals, map[string]any{"foo": "bar"})
}

func (s *connSuite) TestGetAttributeUnhappy(c *C) {
	attrs := map[string]any{}
	var stringVal string
	err := interfaces.GetAttribute("snap0", "iface0", attrs, attrs, "non-existent", &stringVal)
	c.Check(stringVal, Equals, "")
	c.Check(err, ErrorMatches, `snap "snap0" does not have attribute "non-existent" for interface "iface0"`)
	c.Check(errors.Is(err, snap.AttributeNotFoundError{}), Equals, true)
}

func (s *connSuite) TestGetAttributeHappy(c *C) {
	staticAttrs := map[string]any{
		"attr0": "a string",
		"attr1": 12,
	}
	dynamicAttrs := map[string]any{
		"attr0": "second string",
		"attr1": 42,
	}
	var intVal int
	err := interfaces.GetAttribute("snap0", "iface0", staticAttrs, dynamicAttrs, "attr1", &intVal)
	c.Check(err, IsNil)
	c.Check(intVal, Equals, 42)
}

func (s *connSuite) TestPlugLabelExpression(c *C) {
	const snapYaml = `
name: consumer
version: 0
apps:
  app:
    plugs: [plug, app-plug]
plugs:
  plug:
    interface: interface
  comp-plug:
    interface: interface
  app-plug:
    interface: interface
  hook-plug:
    interface: interface
hooks:
  install:
    plugs: [plug, hook-plug]
components:
  comp:
    type: standard
    hooks:
      install:
        plugs: [plug, comp-plug]
`

	const componentYaml = `
component: consumer+comp
type: standard
version: 1
`

	appSet := ifacetest.MockInfoAndAppSet(c, snapYaml, []string{componentYaml}, nil)
	info := appSet.Info()

	// all runnables have it, should use glob
	connectedPlug := interfaces.NewConnectedPlug(info.Plugs["plug"], appSet, nil, nil)
	c.Assert(connectedPlug.LabelExpression(), Equals, `"snap.consumer.*"`)

	// make sure component hooks are considered
	connectedPlug = interfaces.NewConnectedPlug(info.Plugs["comp-plug"], appSet, nil, nil)
	c.Assert(connectedPlug.LabelExpression(), Equals, `"snap.consumer+comp.hook.install"`)

	// make sure apps are considered
	connectedPlug = interfaces.NewConnectedPlug(info.Plugs["app-plug"], appSet, nil, nil)
	c.Assert(connectedPlug.LabelExpression(), Equals, `"snap.consumer.app"`)

	// make sure hooks are considered
	connectedPlug = interfaces.NewConnectedPlug(info.Plugs["hook-plug"], appSet, nil, nil)
	c.Assert(connectedPlug.LabelExpression(), Equals, `"snap.consumer.hook.install"`)
}

func (s *connSuite) TestSlotLabelExpression(c *C) {
	const snapYaml = `
name: producer
version: 0
apps:
  app:
    slots: [slot, app-slot]
slots:
  slot:
  app-slot:
  hook-slot:
hooks:
  install:
    slots: [slot, hook-slot]
components:
  comp:
    type: standard
    hooks:
      install:
`

	const componentYaml = `
component: producer+comp
type: standard
version: 1
`

	appSet := ifacetest.MockInfoAndAppSet(c, snapYaml, []string{componentYaml}, nil)
	info := appSet.Info()

	// components do not have slots right now, so we should not expect a glob
	connectedPlug := interfaces.NewConnectedSlot(info.Slots["slot"], appSet, nil, nil)
	c.Check(connectedPlug.LabelExpression(), Equals, `"snap.producer{.app,.hook.install}"`)

	// make sure apps are considered
	connectedPlug = interfaces.NewConnectedSlot(info.Slots["app-slot"], appSet, nil, nil)
	c.Check(connectedPlug.LabelExpression(), Equals, `"snap.producer.app"`)

	// make sure hooks are considered
	connectedPlug = interfaces.NewConnectedSlot(info.Slots["hook-slot"], appSet, nil, nil)
	c.Check(connectedPlug.LabelExpression(), Equals, `"snap.producer.hook.install"`)
}
