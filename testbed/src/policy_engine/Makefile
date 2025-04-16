all: src/policy_engine.c
	gcc src/policy_engine.c -Wall -Wextra \
		-I./mbedtls/include/ \
		-I ./mbedtls/tf-psa-crypto/include/ \
		-I ./mbedtls/tf-psa-crypto/drivers/builtin/include/ \
		./mbedtls/library/libmbedtls.a \
		./mbedtls/library/libmbedx509.a \
		./mbedtls/library/libmbedcrypto.a \
		$(shell pkg-config --cflags --libs libnl-3.0 libnl-genl-3.0) \
		-o policy_engine
