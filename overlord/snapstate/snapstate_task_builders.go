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

import "github.com/snapcore/snapd/overlord/state"

// builder constructs a graph of tasks with automatic dependency chaining and
// metadata management.
type builder struct {
	// ts contains all tasks managed by this builder and any child span.
	// Primarily, this is used to keep track of edges.
	ts *state.TaskSet
	// tail points to the tip of the current graph. It is updated by the builder
	// or any child spans.
	tail *state.Task
	// meta contains data that tasks added to the graph get adorned with.
	meta map[string]any
}

// newBuilder returns a builder initialized with an empty task set.
func newBuilder() builder {
	return builder{
		ts: state.NewTaskSet(),
	}
}

// TaskSet returns the task set that contains all tasks added to this builder,
// either directly or via child spans.
func (b *builder) TaskSet() *state.TaskSet {
	return b.ts
}

// Add appends a task to the end of the existing chain of tasks. Any existing
// metadata is attached to the given task.
func (b *builder) Add(t *state.Task) {
	tmp := span{b: b}
	tmp.Add(t)
}

// NewSpan creates a new span that shares this builder's task set and tail.
func (b *builder) NewSpan() span {
	return span{b: b}
}

// span represents a logical grouping of tasks within a task builder. This type
// is used to contruct ranges of tasks for easier grouping, while still enabling
// the marking of edges in the parent builder's task set.
type span struct {
	b     *builder
	tasks []*state.Task
}

// SetMetadata sets the metadata applied to all future tasks added to the parent
// builder's task set.
func (s *span) SetMetadata(meta map[string]any) {
	s.b.meta = meta
}

// Add appends a task to graph of tasks managed by the parent builder.
// Additionally, the task is added to this span's range of tasks. The task has
// the builder's metadata applied.
func (s *span) Add(t *state.Task) {
	for k, v := range s.b.meta {
		t.Set(k, v)
	}
	s.AddWithoutMetadata(t)
}

// AddWithoutMetadata behaves the same as Add, but metadata is not applied to
// the added task.
func (s *span) AddWithoutMetadata(t *state.Task) {
	if s.b.tail != nil {
		t.WaitFor(s.b.tail)
	}
	s.b.tail = t
	s.b.ts.AddTask(t)
	s.tasks = append(s.tasks, t)
}

// Splice chains a task into the dependency sequence without adding it to the
// builder's task set or span. This is useful when inserting a task into the
// builder's graph that might be shared by multiple builders.
func (s *span) Splice(t *state.Task) {
	if s.b.tail != nil {
		t.WaitFor(s.b.tail)
	}
	s.b.tail = t
}

// UpdateEdge marks the task as an edge. If the task set owned by the parent
// builder already has that edge, it is overwritten.
func (s *span) UpdateEdge(t *state.Task, e state.TaskSetEdge) {
	s.b.ts.MarkEdge(t, e)
}

func (s *span) UpdateEdgeIfUnset(t *state.Task, e state.TaskSetEdge) {
	if s.b.ts.MaybeEdge(e) != nil {
		return
	}
	s.b.ts.MarkEdge(t, e)
}

// AddTSWithoutMeta adds all tasks from another task set without applying
// metadata. It is assumed that the last task in the task set is the final task
// in it's dependency graph.
func (s *span) AddTSWithoutMeta(ts *state.TaskSet) {
	tasks := ts.Tasks()
	if len(tasks) == 0 {
		return
	}

	if s.b.tail != nil {
		ts.WaitFor(s.b.tail)
	}
	s.b.ts.AddAll(ts)
	s.b.tail = tasks[len(tasks)-1]
	s.tasks = append(s.tasks, ts.Tasks()...)
}

// Tasks returns the tasks owned by this span
func (s *span) Tasks() []*state.Task {
	return s.tasks
}
