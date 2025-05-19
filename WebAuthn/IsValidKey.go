package webauthn


func isValidES256Key(publicKey map[int64]any) bool {
	return publicKey[1].(uint64) == 2 && publicKey[3].(int64) == -7 && publicKey[-1].(uint64) == 1
}

func isValidEdDsaKey(publicKey map[int64]any) bool {
	return publicKey[1].(uint64) == 1 && publicKey[3].(int64) == -8 && publicKey[-1].(uint64) == 6
}

func isValidRS256Key(publicKey map[int64]any) bool {
	return publicKey[1].(uint64) == 3 && publicKey[3].(int64) == -257 && publicKey[-1] != nil
}

func IsValidKey(publicKey map[int64]any) bool {
	return (publicKey[-2] != nil && publicKey[-3] != nil) && (isValidES256Key(publicKey) || isValidEdDsaKey(publicKey) || isValidRS256Key(publicKey))
}
