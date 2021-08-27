package crypt

import (
	"testing"
)

func TestRSA_Encrypt(t *testing.T) {
	instance := NewRSA()
	if err := instance.ImportPublicKey(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcGsUIIAINHfRTdMmgGwLrjzfM
NSrtgIf4EGsNaYwmC1GjF/bMh0Mcm10oLhNrKNYCTTQVGGIxuc5heKd1gOzb7bdT
nCDPPZ7oV7p1B9Pud+6zPacoqDz2M24vHFWYY2FbIIJh8fHhKcfXNXOLovdVBE7Z
y682X1+R1lRK8D+vmQIDAQAB
-----END PUBLIC KEY-----`); err != nil {
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
			args: args{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("got = %v", instance.Encrypt("hello"))
		})
	}
}

func TestRSA_Decrypt(t *testing.T) {
	instance := NewRSA()
	if err := instance.ImportPublicKey(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGrgqLheBZRj4wBZUsBWte0W0O
uwHzHe8LB2rdlg4iIWQXz9ucsPR5FT5qvwr2dmAZaqfo1b7DqBISRV2l1t42H5V/
m1Lp7yBzhlrTk0zglJM6f6b0uiZuMzIQ4LsbtoXpTu+O8rfANWnamADUZO2qj9b1
scyBtiInJQg+JOgJbQIDAQAB
-----END PUBLIC KEY-----`); err != nil {
		panic(err)
	}
	if err := instance.ImportPrivateKey(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDGrgqLheBZRj4wBZUsBWte0W0OuwHzHe8LB2rdlg4iIWQXz9uc
sPR5FT5qvwr2dmAZaqfo1b7DqBISRV2l1t42H5V/m1Lp7yBzhlrTk0zglJM6f6b0
uiZuMzIQ4LsbtoXpTu+O8rfANWnamADUZO2qj9b1scyBtiInJQg+JOgJbQIDAQAB
AoGARp+XIAF2vkU51dgmLn++qvXGznWrO8BoOINqeVndrEQyUESSzCAaxu/GQCuo
ufNaNa60AQ/5v5L+2X/OyiSW2AYH1SSBKKHelUUFJQhAF2R8NLtsVBk3mPz6N99s
KpRgtckt0zClr3D+MdmUPa/PWY8039cazCVBsCF4W/B6NAECQQDk5qTeJLm/H6uN
zggAZPnfYhV1hGJwGqnXEYxCgYXT/oZpUgrhdjj+9KXzmpG94fPZEAY8M4ckRux2
MmqYkYXTAkEA3jN6mnlL7zhwXvDnjvs+69VwYmMaqvjt+txruI3fBZHS9s5vVkHg
/Ek35b02pucKEgwLdagQXxEl5qdv70JrvwJAPvktNmhIKcqeud6K2QDutYQYf0Iy
isDrJN4RBmL33IDTnboSgEC0IYBQ/5nwqpq1KWx9KqbKcTKJ72KjbOHsPQJBAIDB
o9HPZ8j/E15wij24KQXPcIgSlWltRbmP8HvI+eroTS7nAG0jT5PheZqOwhSE3LkI
cbuD37i23xeA/sPN4VECQQDUhlii6+U5nkXCGtvPJgfjBQpwEju8PaAvo+s7P7fW
FqVpnwTf/UJJV9fJkBBrHpoPUrh3R4l/G5cXDauKL7YP
-----END RSA PRIVATE KEY-----`); err != nil {
		panic(err)
	}

	cipherText := instance.Encrypt("hello")

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
			want: "hello",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := instance.Decrypt(tt.args.cipherText); got != tt.want {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRSA_ImportPublicKey(t *testing.T) {
	instance := NewRSA()

	type args struct {
		publicKey string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "",
			args: args{
				publicKey: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGrgqLheBZRj4wBZUsBWte0W0O
uwHzHe8LB2rdlg4iIWQXz9ucsPR5FT5qvwr2dmAZaqfo1b7DqBISRV2l1t42H5V/
m1Lp7yBzhlrTk0zglJM6f6b0uiZuMzIQ4LsbtoXpTu+O8rfANWnamADUZO2qj9b1
scyBtiInJQg+JOgJbQIDAQAB
-----END PUBLIC KEY-----`,
			},
			wantErr: false,
		},
		{
			name: "",
			args: args{
				publicKey: "invalid public key",
			},
			wantErr: true,
		},
		{
			name: "",
			args: args{
				publicKey: `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGrgqLheBZRj4wBZUsBWte0W0O
uwHzHe8LB2rdlg4iIWQXz9uc
-----END PUBLIC KEY-----`, // broken public key
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := instance.ImportPublicKey(tt.args.publicKey); (err != nil) != tt.wantErr {
				t.Errorf("ImportPublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRSA_ImportPrivateKey(t *testing.T) {
	instance := NewRSA()

	type args struct {
		privateKey string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "",
			args: args{
				privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDGrgqLheBZRj4wBZUsBWte0W0OuwHzHe8LB2rdlg4iIWQXz9uc
sPR5FT5qvwr2dmAZaqfo1b7DqBISRV2l1t42H5V/m1Lp7yBzhlrTk0zglJM6f6b0
uiZuMzIQ4LsbtoXpTu+O8rfANWnamADUZO2qj9b1scyBtiInJQg+JOgJbQIDAQAB
AoGARp+XIAF2vkU51dgmLn++qvXGznWrO8BoOINqeVndrEQyUESSzCAaxu/GQCuo
ufNaNa60AQ/5v5L+2X/OyiSW2AYH1SSBKKHelUUFJQhAF2R8NLtsVBk3mPz6N99s
KpRgtckt0zClr3D+MdmUPa/PWY8039cazCVBsCF4W/B6NAECQQDk5qTeJLm/H6uN
zggAZPnfYhV1hGJwGqnXEYxCgYXT/oZpUgrhdjj+9KXzmpG94fPZEAY8M4ckRux2
MmqYkYXTAkEA3jN6mnlL7zhwXvDnjvs+69VwYmMaqvjt+txruI3fBZHS9s5vVkHg
/Ek35b02pucKEgwLdagQXxEl5qdv70JrvwJAPvktNmhIKcqeud6K2QDutYQYf0Iy
isDrJN4RBmL33IDTnboSgEC0IYBQ/5nwqpq1KWx9KqbKcTKJ72KjbOHsPQJBAIDB
o9HPZ8j/E15wij24KQXPcIgSlWltRbmP8HvI+eroTS7nAG0jT5PheZqOwhSE3LkI
cbuD37i23xeA/sPN4VECQQDUhlii6+U5nkXCGtvPJgfjBQpwEju8PaAvo+s7P7fW
FqVpnwTf/UJJV9fJkBBrHpoPUrh3R4l/G5cXDauKL7YP
-----END RSA PRIVATE KEY-----`,
			},
			wantErr: false,
		},
		{
			name: "",
			args: args{
				privateKey: "invalid private key",
			},
			wantErr: true,
		},
		{
			name: "",
			args: args{
				privateKey: `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDGrgqLheBZRj4wBZUsBWte0W0OuwHzHe8LB2rdlg4iIWQXz9uc
sPR5FT5qvwr2dmAZaqfo1b7DqBISRV2l1t42H5V/m1Lp7yBzhlrTk0zglJM6f6b0
uiZuMzIQ4LsbtoXpTu+O8rfANWnamADUZO2qj9b1
-----END RSA PRIVATE KEY-----`, // broken private key
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := instance.ImportPrivateKey(tt.args.privateKey); (err != nil) != tt.wantErr {
				t.Errorf("ImportPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
