package utils

func SlicesAreEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aMap := make(map[string]bool)
	for _, item := range a {
		aMap[item] = true
	}
	for _, item := range b {
		if !aMap[item] {
			return false
		}
	}
	return true
}
