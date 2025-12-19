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

type taskBuilderTestSuite struct{}

var _ = Suite(&taskBuilderTestSuite{})

func (s *taskBuilderTestSuite) TestAddWithMetadata(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newBuilder()
	span := b.NewSpan()

	// this metadata will be applied to all tasks added via this builder or any
	// child spans
	span.SetMetadata(map[string]any{"snap-setup": "snapsup-task"})

	// Add applies the builder's metadata and chains the task to the tail
	t1 := st.NewTask("task-1", "test")
	span.Add(t1)

	var snapsup string
	c.Assert(t1.Get("snap-setup", &snapsup), IsNil)
	c.Check(snapsup, Equals, "snapsup-task")

	c.Check(span.Tasks(), DeepEquals, []*state.Task{t1})
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{t1})

	// Add applies the builder's metadata and chains the task to the tail. note,
	// this is added directly on the builder, so this task should not be a part
	// of the span.
	t2 := st.NewTask("task-2", "test")
	b.Add(t2)

	snapsup = ""
	c.Assert(t2.Get("snap-setup", &snapsup), IsNil)
	c.Check(snapsup, Equals, "snapsup-task")

	c.Check(t2.WaitTasks(), DeepEquals, []*state.Task{t1})
	c.Check(span.Tasks(), DeepEquals, []*state.Task{t1})
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{t1, t2})
}

func (s *taskBuilderTestSuite) TestSpanAddWithoutMetadata(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newBuilder()

	span := b.NewSpan()
	span.SetMetadata(map[string]any{"snap-setup": "snapsup-task"})

	task := st.NewTask("task-1", "test")

	// skips adding metadata but still chains the task
	span.AddWithoutMetadata(task)

	var snapsup string
	c.Check(task.Get("snap-setup", &snapsup), Not(IsNil))
	c.Check(snapsup, Equals, "")

	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{task})
	c.Check(span.Tasks(), DeepEquals, []*state.Task{task})
}

func (s *taskBuilderTestSuite) TestSpanAddChaining(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newBuilder()
	span := b.NewSpan()

	first := st.NewTask("task-1", "first")
	span.Add(first)

	second := st.NewTask("task-2", "second")

	// each task waits for the previous task in the chain
	span.Add(second)

	c.Check(first.WaitTasks(), HasLen, 0)
	c.Check(second.WaitTasks(), DeepEquals, []*state.Task{first})

	// span.tasks tracks all tasks added to this span, in order
	c.Check(span.Tasks(), DeepEquals, []*state.Task{first, second})
}

func (s *taskBuilderTestSuite) TestSpanSplice(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newBuilder()
	span := b.NewSpan()

	first := st.NewTask("task-1", "first")
	span.Add(first)
	second := st.NewTask("task-2", "second")

	// splice chains the task but does not add it to the builder or the span
	span.Splice(second)

	// second waits for first but is not kept around in the builder or the span
	c.Check(second.WaitTasks(), DeepEquals, []*state.Task{first})
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{first})
	c.Check(span.Tasks(), DeepEquals, []*state.Task{first})
}

func (s *taskBuilderTestSuite) TestSpliceSharedTask(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b1 := newBuilder()
	span1 := b1.NewSpan()

	t1 := st.NewTask("task-1", "in-builder-1")
	span1.Add(t1)

	b2 := newBuilder()
	span2 := b2.NewSpan()

	t2 := st.NewTask("task-2", "in-builder-2")
	span2.Add(t2)

	// splice adds the same task to both chains
	spliced := st.NewTask("spliced", "in-both")
	span1.Splice(spliced)
	span2.Splice(spliced)

	// spliced now waits for both task1 and task3, belonging to multiple chains
	c.Check(spliced.WaitTasks(), HasLen, 2)
	c.Check(spliced.WaitTasks()[0], Equals, t1)
	c.Check(spliced.WaitTasks()[1], Equals, t2)

	// but it doesn't belong to either builder task sets. this lets callers
	// safely add the generated task sets to the same change, since a change
	// cannot contain a task more than once.
	c.Check(b1.TaskSet().Tasks(), DeepEquals, []*state.Task{t1})
	c.Check(b2.TaskSet().Tasks(), DeepEquals, []*state.Task{t2})
}

func (s *taskBuilderTestSuite) TestSpanUpdateEdge(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newBuilder()
	span := b.NewSpan()

	first := st.NewTask("task-1", "first")
	span.Add(first)

	edge := state.TaskSetEdge("begin-edge")
	span.UpdateEdge(first, edge)

	edgeTask := b.TaskSet().MaybeEdge(edge)
	c.Check(edgeTask, Equals, first)

	second := st.NewTask("task-2", "second")
	span.Add(second)

	// edges can be overwritten with a different task
	span.UpdateEdge(second, edge)

	edgeTask = b.TaskSet().MaybeEdge(edge)
	c.Check(edgeTask, Equals, second)
}

func (s *taskBuilderTestSuite) TestSpanAddTSWithoutMeta(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newBuilder()
	span := b.NewSpan()

	// add an empty task set, just to make sure we don't panic
	span.AddTSWithoutMeta(state.NewTaskSet())

	first := st.NewTask("task-1", "first")
	span.Add(first)

	second := st.NewTask("task-2", "second")
	third := st.NewTask("task-3", "third")
	third.WaitFor(second)

	// AddTSWithoutMeta adds an entire TaskSet, preserving its internal
	// dependencies
	otherTS := state.NewTaskSet(second, third)
	span.AddTSWithoutMeta(otherTS)

	fourth := st.NewTask("task-4", "fourth")
	span.Add(fourth)

	// third and second both wait for first, and third waits for second (the
	// original chain within the task set)
	c.Check(second.WaitTasks(), DeepEquals, []*state.Task{first})
	c.Check(third.WaitTasks(), DeepEquals, []*state.Task{second, first})

	// fourth waits on the tail of the added task set, third
	c.Check(fourth.WaitTasks(), DeepEquals, []*state.Task{third})

	// all tasks are contained within the builder and span
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{first, second, third, fourth})
	c.Check(span.Tasks(), DeepEquals, []*state.Task{first, second, third, fourth})
}

func (s *taskBuilderTestSuite) TestMultipleSpansShareBuilder(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newBuilder()

	span1 := b.NewSpan()

	first := st.NewTask("task-1", "first")
	span1.Add(first)

	span2 := b.NewSpan()

	second := st.NewTask("task-2", "second")
	span2.Add(second)

	third := st.NewTask("task-3", "third")
	span2.Add(third)

	c.Check(first.WaitTasks(), HasLen, 0)

	// both spans share the same task set and tail, forming a single chain
	c.Check(second.WaitTasks(), DeepEquals, []*state.Task{first})
	c.Check(third.WaitTasks(), DeepEquals, []*state.Task{second})
	c.Check(b.TaskSet().Tasks(), DeepEquals, []*state.Task{first, second, third})

	// each span tracks only the tasks it added, enabling callers to keep track
	// of ranges
	c.Check(span1.Tasks(), DeepEquals, []*state.Task{first})
	c.Check(span2.Tasks(), DeepEquals, []*state.Task{second, third})
}

func (s *taskBuilderTestSuite) TestSpanUpdateEdgeIfUnset(c *C) {
	st := state.New(nil)
	st.Lock()
	defer st.Unlock()

	b := newBuilder()
	span := b.NewSpan()

	first := st.NewTask("task-1", "first")
	second := st.NewTask("task-2", "second")

	edge := state.TaskSetEdge("begin-edge")

	// edge gets set when it's unset
	span.UpdateEdgeIfUnset(first, edge)

	edgeTask := b.TaskSet().MaybeEdge(edge)
	c.Check(edgeTask, Equals, first)

	// attempting to set the same edge again does nothing
	span.UpdateEdgeIfUnset(second, edge)

	edgeTask = b.TaskSet().MaybeEdge(edge)
	c.Check(edgeTask, Equals, first)
}
