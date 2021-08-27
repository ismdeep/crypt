package crypt

import (
	"fmt"
	"testing"
)

func TestGenKey(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenAESKey()
			fmt.Println(got)
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		key  string
		mode string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "",
			args: args{
				key:  GenAESKey(),
				mode: AESModeCBC,
			},
			wantErr: false,
		},
		{
			name: "",
			args: args{
				key:  GenAESKey(),
				mode: "invalid mode",
			},
			wantErr: true,
		},
		{
			name: "",
			args: args{
				key:  "1", // invalid key
				mode: AESModeCBC,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAES(tt.args.key, tt.args.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAES() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestAES_CBC_Encrypt(t *testing.T) {
	receiver, err := NewAES(GenAESKey(), AESModeCBC)
	if err != nil {
		panic(err)
	}

	type args struct {
		plainText string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "",
			args: args{
				plainText: "hello",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("got = %v", receiver.Encrypt(tt.args.plainText))
		})
	}
}

func TestAES_CBC_Decrypt(t *testing.T) {
	receiver, err := NewAES(GenAESKey(), AESModeCBC)
	if err != nil {
		panic(err)
	}

	cipherText := receiver.Encrypt("hello, world.")

	type args struct {
		cipherText string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "",
			args: args{
				cipherText: cipherText,
			},
			want: "hello, world.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := receiver.Decrypt(tt.args.cipherText); got != tt.want {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAES_CRT_Encrypt(t *testing.T) {
	receiver, err := NewAES(GenAESKey(), AESModeCTR)
	if err != nil {
		panic(err)
	}

	type args struct {
		plainText string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "",
			args: args{
				plainText: "Hello, world.",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("got = %v", receiver.Encrypt(tt.args.plainText))
		})
	}
}

func TestAES_CRT_Decrypt(t *testing.T) {
	receiver, err := NewAES(GenAESKey(), AESModeCTR)
	if err != nil {
		panic(err)
	}

	cipherText := receiver.Encrypt("hello, world.")

	type args struct {
		cipherText string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "",
			args: args{
				cipherText: cipherText,
			},
			want: "hello, world.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := receiver.Decrypt(tt.args.cipherText); got != tt.want {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAES_CFB_Encrypt(t *testing.T) {
	receiver, err := NewAES(GenAESKey(), AESModeCFB)
	if err != nil {
		panic(err)
	}

	type args struct {
		plainText string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "",
			args: args{
				plainText: "hello",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("got = %v", receiver.Encrypt(tt.args.plainText))
		})
	}
}

func TestAES_CFB_Decrypt(t *testing.T) {
	receiver, err := NewAES(GenAESKey(), AESModeCFB)
	if err != nil {
		panic(err)
	}

	cipherText := receiver.Encrypt("hello, world.")

	type args struct {
		cipherText string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "",
			args: args{
				cipherText: cipherText,
			},
			want: "hello, world.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := receiver.Decrypt(tt.args.cipherText); got != tt.want {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAES_OFB_Encrypt(t *testing.T) {
	receiver, err := NewAES(GenAESKey(), AESModeOFB)
	if err != nil {
		panic(err)
	}

	type args struct {
		plainText string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "",
			args: args{
				plainText: "hello",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("got = %v", receiver.Encrypt(tt.args.plainText))
		})
	}
}

func TestAES_OFB_Decrypt(t *testing.T) {
	receiver, err := NewAES(GenAESKey(), AESModeOFB)
	if err != nil {
		panic(err)
	}

	cipherText := receiver.Encrypt("hello, world.")

	type args struct {
		cipherText string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "",
			args: args{
				cipherText: cipherText,
			},
			want: "hello, world.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := receiver.Decrypt(tt.args.cipherText); got != tt.want {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
