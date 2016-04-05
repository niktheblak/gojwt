package sign

func None() Algorithm {
	return Algorithms["none"]
}

func HS256() Algorithm {
	return Algorithms["HS256"]
}
