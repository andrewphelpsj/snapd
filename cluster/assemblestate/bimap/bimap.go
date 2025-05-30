package bimap

type BiMap[V comparable, I ~int] struct {
	values  []V
	indexes map[V]I
}

func New[V comparable, I ~int]() *BiMap[V, I] {
	return &BiMap[V, I]{
		values:  make([]V, 0),
		indexes: make(map[V]I),
	}
}

func (bm *BiMap[V, I]) Add(v V) I {
	if idx, exists := bm.indexes[v]; exists {
		return idx
	}

	index := I(len(bm.values))
	bm.values = append(bm.values, v)
	bm.indexes[v] = index

	return index
}

func (bm *BiMap[V, I]) IndexOf(v V) (I, bool) {
	idx, exists := bm.indexes[v]
	return idx, exists
}

func (bm *BiMap[V, I]) Value(i I) V {
	return bm.values[i]
}

func (bm *BiMap[V, I]) Values() []V {
	copied := make([]V, len(bm.values))
	copy(copied, bm.values)
	return copied
}
