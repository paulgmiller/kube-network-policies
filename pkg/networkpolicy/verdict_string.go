// Code generated by "stringer -type=Verdict"; DO NOT EDIT.

package networkpolicy

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Drop-0]
	_ = x[Accept-1]
}

const _Verdict_name = "DropAccept"

var _Verdict_index = [...]uint8{0, 4, 10}

func (i Verdict) String() string {
	if i < 0 || i >= Verdict(len(_Verdict_index)-1) {
		return "Verdict(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Verdict_name[_Verdict_index[i]:_Verdict_index[i+1]]
}