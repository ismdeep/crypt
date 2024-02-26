package core

func PanicIf(err error) {
	if err != nil {
		panic(err)
	}
}

func LastErr(items ...any) error {
	var err error
	for _, item := range items {
		if e, ok := item.(error); ok {
			err = e
		}
	}
	return err
}

func IfErr(flag bool, err error) error {
	if flag {
		return err
	}
	return nil
}
