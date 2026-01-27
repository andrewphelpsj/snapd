// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
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

package snapstate

import (
	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/overlord/state"
)

type taskChainBuilderTestSuite struct{}

var _ = Suite(&taskChainBuilderTestSuite{})

func (s *taskChainBuilderTestSuite) TestAppendWithTaskData(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()

	// this task data will be applied to all tasks added via this taskChainBuilder or any
	// child taskChainSpans
	t1 := st.NewTask("task-1", "test")
	spanTasks, err := b.Span(func(s *taskChainSpan) error {
		s.SetTaskData(map[string]any{"snap-setup": "snapsup-task"})

		// Append applies the taskChainBuilder's task data and chains the task to the tail
		s.Append(t1)
		return nil
	})
	c.Assert(err, IsNil)

	var snapsup string
	c.Assert(t1.Get("snap-setup", &snapsup), IsNil)
	c.Check(snapsup, Equals, "snapsup-task")

	c.Check(spanTasks, DeepEquals, []*state.Task{t1})
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{t1})

	// Append applies the taskChainBuilder's task data and chains the task to the tail. note,
	// this is added directly on the taskChainBuilder, so this task should not be a part
	// of the taskChainSpan.
	t2 := st.NewTask("task-2", "test")
	b.Append(t2)

	snapsup = ""
	c.Assert(t2.Get("snap-setup", &snapsup), IsNil)
	c.Check(snapsup, Equals, "snapsup-task")

	c.Check(t2.WaitTasks(), DeepEquals, []*state.Task{t1})
	c.Check(spanTasks, DeepEquals, []*state.Task{t1})
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{t1, t2})
}

func (s *taskChainBuilderTestSuite) TestSpanAppendWithoutData(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()

	task := st.NewTask("task-1", "test")
	spanTasks, err := b.Span(func(s *taskChainSpan) error {
		s.SetTaskData(map[string]any{"snap-setup": "snapsup-task"})

		// skips adding task data but still chains the task
		s.AppendWithoutData(task)
		return nil
	})
	c.Assert(err, IsNil)

	var snapsup string
	c.Check(task.Get("snap-setup", &snapsup), Not(IsNil))
	c.Check(snapsup, Equals, "")

	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{task})
	c.Check(spanTasks, DeepEquals, []*state.Task{task})
}

func (s *taskChainBuilderTestSuite) TestSpanAppendChaining(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()
	first := st.NewTask("task-1", "first")
	second := st.NewTask("task-2", "second")
	spanTasks, err := b.Span(func(s *taskChainSpan) error {
		s.Append(first)

		// each task waits for the previous task in the chain
		s.Append(second)
		return nil
	})
	c.Assert(err, IsNil)

	c.Check(first.WaitTasks(), HasLen, 0)
	c.Check(second.WaitTasks(), DeepEquals, []*state.Task{first})

	// taskChainSpan.tasks tracks all tasks added to this taskChainSpan, in order
	c.Check(spanTasks, DeepEquals, []*state.Task{first, second})
}

func (s *taskChainBuilderTestSuite) TestSpanChainWithoutAppending(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()
	first := st.NewTask("task-1", "first")
	spanTasks, err := b.Span(func(s *taskChainSpan) error {
		s.Append(first)
		return nil
	})
	c.Assert(err, IsNil)
	second := st.NewTask("task-2", "second")

	// ChainWithoutAppending chains the task but does not add it to the taskChainBuilder or the taskChainSpan
	b.JoinOn(second)

	// second waits for first but is not kept around in the taskChainBuilder or the taskChainSpan
	c.Check(second.WaitTasks(), DeepEquals, []*state.Task{first})
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{first})
	c.Check(spanTasks, DeepEquals, []*state.Task{first})
}

func (s *taskChainBuilderTestSuite) TestChainWithoutAppendingSharedTask(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b1 := newTaskChainBuilder()
	t1 := st.NewTask("task-1", "in-taskChainBuilder-1")
	span1Tasks, err := b1.Span(func(s *taskChainSpan) error {
		s.Append(t1)
		return nil
	})
	c.Assert(err, IsNil)

	b2 := newTaskChainBuilder()
	t2 := st.NewTask("task-2", "in-taskChainBuilder-2")
	span2Tasks, err := b2.Span(func(s *taskChainSpan) error {
		s.Append(t2)
		return nil
	})
	c.Assert(err, IsNil)

	// ChainWithoutAppending adds the same task to both chains
	chained := st.NewTask("chained", "in-both")
	b1.JoinOn(chained)
	b2.JoinOn(chained)

	// chained now waits for both task1 and task3, belonging to multiple chains
	c.Check(chained.WaitTasks(), HasLen, 2)
	c.Check(chained.WaitTasks()[0], Equals, t1)
	c.Check(chained.WaitTasks()[1], Equals, t2)

	// but it doesn't belong to either taskChainBuilder task sets. this lets callers
	// safely add the generated task sets to the same change, since a change
	// cannot contain a task more than once.
	c.Check(b1.TaskSet().Tasks(), DeepEquals, []*state.Task{t1})
	c.Check(b2.TaskSet().Tasks(), DeepEquals, []*state.Task{t2})
	c.Check(span1Tasks, DeepEquals, []*state.Task{t1})
	c.Check(span2Tasks, DeepEquals, []*state.Task{t2})
}

func (s *taskChainBuilderTestSuite) TestSpanUpdateEdge(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()
	edge := state.TaskSetEdge("begin-edge")
	first := st.NewTask("task-1", "first")
	second := st.NewTask("task-2", "second")
	var edgeTaskAfterFirst *state.Task
	_, err := b.Span(func(s *taskChainSpan) error {
		s.Append(first)

		s.UpdateEdge(first, edge)
		edgeTaskAfterFirst = b.TaskSet().MaybeEdge(edge)

		s.Append(second)

		// edges can be overwritten with a different task
		s.UpdateEdge(second, edge)
		return nil
	})
	c.Assert(err, IsNil)
	c.Check(edgeTaskAfterFirst, Equals, first)

	edgeTask := b.TaskSet().MaybeEdge(edge)
	c.Check(edgeTask, Equals, second)
}

func (s *taskChainBuilderTestSuite) TestSpanUpdateEdgeIfUnset(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()
	edge := state.TaskSetEdge("begin-edge")
	first := st.NewTask("task-1", "first")
	second := st.NewTask("task-2", "second")
	var edgeTaskAfterFirst *state.Task
	_, err := b.Span(func(s *taskChainSpan) error {
		// edge gets set when it's unset
		s.UpdateEdgeIfUnset(first, edge)
		edgeTaskAfterFirst = b.TaskSet().MaybeEdge(edge)

		// attempting to set the same edge again does nothing
		s.UpdateEdgeIfUnset(second, edge)
		return nil
	})
	c.Assert(err, IsNil)
	c.Check(edgeTaskAfterFirst, Equals, first)

	edgeTask := b.TaskSet().MaybeEdge(edge)
	c.Check(edgeTask, Equals, first)
}

func (s *taskChainBuilderTestSuite) TestSpanAppendTSWithoutData(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()

	first := st.NewTask("first", "first")

	// create a diamond-shaped section of the graph:
	//     t2
	//    /  \
	// t1      t4
	//    \  /
	//     t3
	t1 := st.NewTask("t1", "head of diamond")
	t2 := st.NewTask("t2", "left branch")
	t3 := st.NewTask("t3", "right branch")
	t4 := st.NewTask("t4", "tail of diamond")
	t2.WaitFor(t1)
	t3.WaitFor(t1)
	t4.WaitFor(t2)
	t4.WaitFor(t3)

	last := st.NewTask("last", "last")

	spanTasks, err := b.Span(func(s *taskChainSpan) error {
		// add an empty task set, just to make sure we don't panic
		s.AppendTSWithoutData(state.NewTaskSet())

		s.Append(first)

		// AppendTSWithoutData adds an entire TaskSet, preserving its internal
		// dependencies. only head tasks wait for the current tail, and only tail
		// tasks become the new tail.
		s.AppendTSWithoutData(state.NewTaskSet(t1, t2, t3, t4))

		s.Append(last)

		return nil
	})
	c.Assert(err, IsNil)

	// t1 waits for first
	c.Check(t1.WaitTasks(), DeepEquals, []*state.Task{first})

	// t2 and t3 only wait for t1 (their original dependencies within the task set)
	c.Check(t2.WaitTasks(), DeepEquals, []*state.Task{t1})
	c.Check(t3.WaitTasks(), DeepEquals, []*state.Task{t1})

	// t4 waits for t2 and t3 (its original dependencies within the task set)
	c.Check(t4.WaitTasks(), DeepEquals, []*state.Task{t2, t3})

	// last waits only on t4, not all tasks in the task set
	c.Check(last.WaitTasks(), DeepEquals, []*state.Task{t4})

	// all tasks are contained within the taskChainBuilder and taskChainSpan
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{first, t1, t2, t3, t4, last})
	c.Check(spanTasks, DeepEquals, []*state.Task{first, t1, t2, t3, t4, last})
}

func (s *taskChainBuilderTestSuite) TestSpanAppendTSWithoutDataOrdersTasks(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()

	t1 := st.NewTask("t1", "first")
	t2 := st.NewTask("t2", "second")
	t3 := st.NewTask("t3", "third")
	t2.WaitFor(t1)
	t3.WaitFor(t2)

	otherTS := state.NewTaskSet(t2, t1, t3)

	spanTasks, err := b.Span(func(s *taskChainSpan) error {
		s.AppendTSWithoutData(otherTS)
		return nil
	})
	c.Assert(err, IsNil)

	c.Check(spanTasks, DeepEquals, []*state.Task{t1, t2, t3})
}

func (s *taskChainBuilderTestSuite) TestSpanAppendTSWithoutDataOrdersDiamondTasks(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()

	// create a diamond-shaped section of the graph:
	//     t2
	//    /  \
	// t1      t4
	//    \  /
	//     t3
	t1 := st.NewTask("t1", "head of diamond")
	t2 := st.NewTask("t2", "left branch")
	t3 := st.NewTask("t3", "right branch")
	t4 := st.NewTask("t4", "tail of diamond")
	t2.WaitFor(t1)
	t3.WaitFor(t1)
	t4.WaitFor(t2)
	t4.WaitFor(t3)

	// create task set with a shuffled order
	otherTS := state.NewTaskSet(t3, t1, t4, t2)

	spanTasks, err := b.Span(func(s *taskChainSpan) error {
		s.AppendTSWithoutData(otherTS)
		return nil
	})
	c.Assert(err, IsNil)

	c.Assert(spanTasks, HasLen, 4)

	// ensure we put the head of the diamond first, and the tail last. this is
	// despite intentionally adding the tasks to the task set out of order
	c.Check(spanTasks[0], Equals, t1)
	c.Check(spanTasks[len(spanTasks)-1], Equals, t4)
}

func (s *taskChainBuilderTestSuite) TestSpanAppendTSWithoutDataSingleTaskOrder(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()

	t1 := st.NewTask("t1", "only task")
	otherTS := state.NewTaskSet(t1)

	spanTasks, err := b.Span(func(s *taskChainSpan) error {
		s.AppendTSWithoutData(otherTS)
		return nil
	})
	c.Assert(err, IsNil)

	c.Check(spanTasks, DeepEquals, []*state.Task{t1})
}

func (s *taskChainBuilderTestSuite) TestSpanAppendTSWithoutDataMultipleHeadsPanics(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()

	t1 := st.NewTask("t1", "head-1")
	t2 := st.NewTask("t2", "head-2")
	otherTS := state.NewTaskSet(t1, t2)

	c.Check(func() {
		_, _ = b.Span(func(s *taskChainSpan) error {
			s.AppendTSWithoutData(otherTS)
			return nil
		})
	}, PanicMatches, `internal error: cannot start task chain span with multiple heads`)
}

func (s *taskChainBuilderTestSuite) TestSpanMultipleTailsPanics(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()

	t1 := st.NewTask("t1", "head")
	t2 := st.NewTask("t2", "tail-1")
	t3 := st.NewTask("t3", "tail-2")
	t2.WaitFor(t1)
	t3.WaitFor(t1)
	otherTS := state.NewTaskSet(t1, t2, t3)

	c.Check(func() {
		_, _ = b.Span(func(s *taskChainSpan) error {
			s.AppendTSWithoutData(otherTS)
			return nil
		})
	}, PanicMatches, `internal error: cannot end task chain span with multiple tails`)
}

func (s *taskChainBuilderTestSuite) TestMultipleSpansShareTaskChainBuilder(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newTaskChainBuilder()
	first := st.NewTask("task-1", "first")
	second := st.NewTask("task-2", "second")
	third := st.NewTask("task-3", "third")
	span1Tasks, err := b.Span(func(s *taskChainSpan) error {
		s.Append(first)
		return nil
	})
	c.Assert(err, IsNil)

	span2Tasks, err := b.Span(func(s *taskChainSpan) error {
		s.Append(second)

		s.Append(third)
		return nil
	})
	c.Assert(err, IsNil)

	c.Check(first.WaitTasks(), HasLen, 0)

	// both taskChainSpans share the same task set and tail, forming a single chain
	c.Check(second.WaitTasks(), DeepEquals, []*state.Task{first})
	c.Check(third.WaitTasks(), DeepEquals, []*state.Task{second})
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{first, second, third})

	// each taskChainSpan tracks only the tasks it added, enabling callers to keep track
	// of ranges
	c.Check(span1Tasks, DeepEquals, []*state.Task{first})
	c.Check(span2Tasks, DeepEquals, []*state.Task{second, third})
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksEmpty(c *C) {
	ts := state.NewTaskSet()
	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	c.Check(heads, IsNil)
	c.Check(tails, IsNil)
	c.Check(remainder, IsNil)
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksSingle(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	t1 := st.NewTask("task-1", "only task")
	ts := state.NewTaskSet(t1)

	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	c.Check(heads, DeepEquals, []*state.Task{t1})
	c.Check(tails, DeepEquals, []*state.Task{t1})
	c.Check(remainder, IsNil)
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksLinearChain(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	// T1 -> T2 -> T3
	t1 := st.NewTask("task-1", "first")
	t2 := st.NewTask("task-2", "second")
	t3 := st.NewTask("task-3", "third")
	t2.WaitFor(t1)
	t3.WaitFor(t2)

	ts := state.NewTaskSet(t1, t2, t3)

	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	c.Check(heads, DeepEquals, []*state.Task{t1})
	c.Check(tails, DeepEquals, []*state.Task{t3})
	c.Check(remainder, DeepEquals, []*state.Task{t2})
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksDiamond(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	// T1 -> T2 -> T4
	//  \ -> T3 -> /
	t1 := st.NewTask("task-1", "first")
	t2 := st.NewTask("task-2", "second")
	t3 := st.NewTask("task-3", "third")
	t4 := st.NewTask("task-4", "fourth")
	t2.WaitFor(t1)
	t3.WaitFor(t1)
	t4.WaitFor(t2)
	t4.WaitFor(t3)

	ts := state.NewTaskSet(t1, t2, t3, t4)

	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	c.Check(heads, DeepEquals, []*state.Task{t1})
	c.Check(tails, DeepEquals, []*state.Task{t4})
	c.Check(remainder, DeepEquals, []*state.Task{t2, t3})
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksDisconnected(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	// T1 and T2 have no dependencies between them
	t1 := st.NewTask("task-1", "first")
	t2 := st.NewTask("task-2", "second")

	ts := state.NewTaskSet(t1, t2)

	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	c.Check(heads, DeepEquals, []*state.Task{t1, t2})
	c.Check(tails, DeepEquals, []*state.Task{t1, t2})
	c.Check(remainder, IsNil)
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksMultipleHeads(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	// T1 -> T3
	// T2 -> /
	t1 := st.NewTask("task-1", "first")
	t2 := st.NewTask("task-2", "second")
	t3 := st.NewTask("task-3", "third")
	t3.WaitFor(t1)
	t3.WaitFor(t2)

	ts := state.NewTaskSet(t1, t2, t3)

	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	c.Check(heads, DeepEquals, []*state.Task{t1, t2})
	c.Check(tails, DeepEquals, []*state.Task{t3})
	c.Check(remainder, IsNil)
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksMultipleTails(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	// T1 -> T2
	//  \ -> T3
	t1 := st.NewTask("task-1", "first")
	t2 := st.NewTask("task-2", "second")
	t3 := st.NewTask("task-3", "third")
	t2.WaitFor(t1)
	t3.WaitFor(t1)

	ts := state.NewTaskSet(t1, t2, t3)

	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	c.Check(heads, DeepEquals, []*state.Task{t1})
	c.Check(tails, DeepEquals, []*state.Task{t2, t3})
	c.Check(remainder, IsNil)
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksTwoChains(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	// two independent chains:
	// T1 -> T2 -> T3
	// T4 -> T5 -> T6
	t1 := st.NewTask("task-1", "first")
	t2 := st.NewTask("task-2", "second")
	t3 := st.NewTask("task-3", "third")
	t4 := st.NewTask("task-4", "fourth")
	t5 := st.NewTask("task-5", "fifth")
	t6 := st.NewTask("task-6", "sixth")

	t2.WaitFor(t1)
	t3.WaitFor(t2)
	t5.WaitFor(t4)
	t6.WaitFor(t5)

	ts := state.NewTaskSet(t1, t2, t3, t4, t5, t6)

	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	c.Check(heads, DeepEquals, []*state.Task{t1, t4})
	c.Check(tails, DeepEquals, []*state.Task{t3, t6})
	c.Check(remainder, DeepEquals, []*state.Task{t2, t5})
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksIgnoresExternalDeps(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	// T1 -> T2 -> T3, but T2 also waits for external task
	t1 := st.NewTask("task-1", "first")
	t2 := st.NewTask("task-2", "second")
	t3 := st.NewTask("task-3", "third")
	external := st.NewTask("external", "not in set")

	t2.WaitFor(t1)
	t2.WaitFor(external)
	t3.WaitFor(t2)

	// only include t1, t2, t3 in the set (not external)
	ts := state.NewTaskSet(t1, t2, t3)

	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	// t1 is still the only head (external dep is ignored)
	c.Check(heads, DeepEquals, []*state.Task{t1})
	c.Check(tails, DeepEquals, []*state.Task{t3})
	c.Check(remainder, DeepEquals, []*state.Task{t2})
}

func (s *taskChainBuilderTestSuite) TestFindHeadAndTailTasksWithExternalWaitAndHalt(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	// external-1 -> t1 -> t2 -> external-2
	external1 := st.NewTask("external-1", "external predecessor")
	t1 := st.NewTask("task-1", "first in set")
	t2 := st.NewTask("task-2", "second in set")
	external2 := st.NewTask("external-2", "external successor")

	t1.WaitFor(external1)
	t2.WaitFor(t1)
	external2.WaitFor(t2)

	// only include t1, t2 in the set
	ts := state.NewTaskSet(t1, t2)

	heads, tails, remainder := findHeadAndTailTasks(ts.Tasks())
	// t1 is still the head (external predecessor is ignored)
	c.Check(heads, DeepEquals, []*state.Task{t1})
	// t2 is still the tail (external successor is ignored)
	c.Check(tails, DeepEquals, []*state.Task{t2})
	c.Check(remainder, IsNil)
}
