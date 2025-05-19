package webauthn

import "fmt"

func isValidES256Key(publicKey map[any]any) bool {
	return publicKey[1].(int) == 2 && publicKey[3].(int) == -7 && publicKey[-1].(int) == 1
}

func isValidEdDsaKey(publicKey map[any]any) bool {
	return publicKey[1] == 1 && publicKey[3] == -8 && publicKey[-1] == 6
}

func isValidRS256Key(publicKey map[any]any) bool {
	return publicKey[1] == 3 && publicKey[3] == -257 && publicKey[-1] != nil
}

func IsValidKey(publicKey map[any]any) bool {
	fmt.Println(publicKey[-2] != nil)

	return (publicKey[-2] != nil && publicKey[-3] != nil) && (isValidES256Key(publicKey) || isValidEdDsaKey(publicKey) || isValidRS256Key(publicKey))
}
