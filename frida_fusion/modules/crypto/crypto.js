
const CRYPTO_MODULES = {
    KeyGenerator: true,
    KeyPairGenerator: true,
    SecretKeySpec: true,
    MessageDigest: true,
    SecretKeyFactory: true,
    Signature: true,
    Cipher: true,
    Mac: true,
    KeyGenParameterSpec: true,
    IvParameterSpec: true,
    GCMParameterSpec: true,
    PBEParameterSpec: true,
    X509EncodedKeySpec: true
};

setTimeout(function() {
    Java.perform(function() {

        const System = Java.use("java.lang.System");

        if (CRYPTO_MODULES.KeyGenerator) {
            fusion_sendMessage('*', "Module attached: javax.crypto.KeyGenerator");
            const keyGenerator = Java.use("javax.crypto.KeyGenerator");

            keyGenerator.generateKey.implementation = function () {
                fusion_sendMessage('*', "keyGenerator.generateKey");
                return this.generateKey();
            };

            keyGenerator.getInstance.overload("java.lang.String").implementation = function (arg0) {
                fusion_sendKeyValueData("keyGenerator.getInstance", [
                    {key: "Algorithm", value: arg0}
                ]);
                return this.getInstance(arg0);
            };

            keyGenerator.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("keyGenerator.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

            keyGenerator.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("keyGenerator.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

        }

        if (CRYPTO_MODULES.KeyPairGenerator) {
            fusion_sendMessage('*', "Module attached: java.security.KeyPairGenerator");
            const keyPairGenerator = Java.use("java.security.KeyPairGenerator");
            keyPairGenerator.getInstance.overload("java.lang.String").implementation = function (arg0) {
                fusion_sendKeyValueData("keyPairGenerator.getInstance", [
                    {key: "Algorithm", value: arg0}
                ]);
                return this.getInstance(arg0);
            };

            keyPairGenerator.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("keyPairGenerator.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

            keyPairGenerator.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("keyPairGenerator.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };
        }

        if (CRYPTO_MODULES.SecretKeySpec) {
            fusion_sendMessage('*', "Module attached: javax.crypto.spec.SecretKeySpec");
            const secretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
            secretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, cipher) {
                const keyBase64 = fusion_bytesToBase64(key);
                fusion_sendKeyValueData("SecretKeySpec.init", [
                    {key: "Key", value: keyBase64},
                    {key: "Algorithm", value: cipher},
                    {key: "ClassType", value: fusion_getClassName(this)}
                ]);
                return secretKeySpec.$init.overload("[B", "java.lang.String").call(this, key, cipher);
            }
        }

        if (CRYPTO_MODULES.MessageDigest) {
            fusion_sendMessage('*', "Module attached: java.security.MessageDigest");
            const messageDigest = Java.use("java.security.MessageDigest");
            messageDigest.getInstance.overload("java.lang.String").implementation = function (arg0) {
                fusion_sendKeyValueData("messageDigest.getInstance", [
                    {key: "Algorithm", value: arg0}
                ]);
                return this.getInstance(arg0);
            };

            messageDigest.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("messageDigest.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

            messageDigest.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("messageDigest.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

            messageDigest.update.overload("[B").implementation = function (input) {
                const inputBase64 = fusion_bytesToBase64(input);
                fusion_sendKeyValueData("messageDigest.update", [
                    {key: "HashCode", value: System.identityHashCode(this)},
                    {key: "Input", value: inputBase64},
                    {key: "Algorithm", value: this.getAlgorithm()}
                ]);
                return this.update.overload("[B").call(this, input);
            };

            messageDigest.digest.overload().implementation = function () {
                const output = messageDigest.digest.overload().call(this);
                const outputBase64 = fusion_bytesToBase64(output);
                fusion_sendKeyValueData("messageDigest.digest", [
                    {key: "HashCode", value: System.identityHashCode(this)},
                    {key: "Output", value: outputBase64},
                    {key: "Algorithm", value: this.getAlgorithm()}
                ]);
                return output;
            };

        }

        if (CRYPTO_MODULES.SecretKeyFactory) {
            fusion_sendMessage('*', "Module attached: javax.crypto.SecretKeyFactory");
            const secretKeyFactory = Java.use("javax.crypto.SecretKeyFactory");
            secretKeyFactory.getInstance.overload("java.lang.String").implementation = function (arg0) {
                fusion_sendKeyValueData("SecretKeyFactory.getInstance", [
                    {key: "Algorithm", value: arg0}
                ]);
                return this.getInstance(arg0);
            };

            secretKeyFactory.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("SecretKeyFactory.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

            secretKeyFactory.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("SecretKeyFactory.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };
        }

        if (CRYPTO_MODULES.Signature) {
            fusion_sendMessage('*', "Module attached: java.security.Signature");
            const signature = Java.use("java.security.Signature");
            signature.getInstance.overload("java.lang.String").implementation = function (arg0) {
                fusion_sendKeyValueData("signature.getInstance", [
                    {key: "Algorithm", value: arg0}
                ]);
                return this.getInstance(arg0);
            };

            signature.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("signature.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

            signature.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("signature.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };
        }

        if (CRYPTO_MODULES.Cipher) {
            fusion_sendMessage('*', "Module attached: javax.crypto.Cipher");
            var iv_parameter_spec = Java.use("javax.crypto.spec.IvParameterSpec");
            var pbe_parameter_spec = Java.use("javax.crypto.spec.PBEParameterSpec");
            var gcm_parameter_spec = Java.use("javax.crypto.spec.GCMParameterSpec");
            const cipher = Java.use("javax.crypto.Cipher");
            cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
                fusion_sendKeyValueData("cipher.init", [
                    {key: "HashCode", value: this.hashCode().toString()},
                    {key: "Key", value: fusion_keyToBase64(key)},
                    {key: "KeyType", value: fusion_getClassName(key)},
                    {key: "Opmode", value: this.getOpmodeString(opmode)},
                    {key: "Algorithm", value: this.getAlgorithm()}
                ]);
                this.init.overload("int", "java.security.Key").call(this, opmode, key);
            }

            cipher.init.overload("int", "java.security.cert.Certificate").implementation = function (opmode, certificate) {
                fusion_sendKeyValueData("cipher.init", [
                    {key: "HashCode", value: this.hashCode().toString()},
                    {key: "Key", value: fusion_keyToBase64(certificate)},
                    {key: "Certificate", value: fusion_keyToBase64(certificate)},
                    {key: "KeyType", value: fusion_getClassName(certificate)},
                    {key: "Opmode", value: this.getOpmodeString(opmode)},
                    {key: "Algorithm", value: this.getAlgorithm()}
                ]);
                this.init.overload("int", "java.security.cert.Certificate").call(this, opmode, certificate);
            }

            cipher.init.overload("int", "java.security.Key", "java.security.AlgorithmParameters").implementation = function (opmode, key, algorithmParameter) {
                fusion_sendKeyValueData("cipher.init", [
                    {key: "HashCode", value: this.hashCode().toString()},
                    {key: "Key", value: fusion_keyToBase64(key)},
                    {key: "KeyType", value: fusion_getClassName(key)},
                    {key: "Opmode", value: this.getOpmodeString(opmode)},
                    {key: "Algorithm", value: this.getAlgorithm()}
                ]);
                this.init.overload("int", "java.security.Key", "java.security.AlgorithmParameters").call(this, opmode, key, algorithmParameter);
            }

            cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opmode, key, algorithmParameter) {
                
                try{
                    var data = [
                        {key: "HashCode", value: this.hashCode().toString()},
                        {key: "Key", value: fusion_keyToBase64(key)},
                        {key: "KeyType", value: fusion_getClassName(key)},
                        {key: "Opmode", value: this.getOpmodeString(opmode)},
                        {key: "Algorithm", value: this.getAlgorithm()}
                    ];

                    //arg algorithmParameter is of type AlgorithmParameterSpec, we need to cast it to IvParameterSpec first to be able to call getIV function
                    //Se não for AES vai dar pau
                    //Cast from javax.crypto.spec.PBEParameterSpec to javax.crypto.spec.IvParameterSpec
                    try{
                        data = data.concat([
                            {key: "IV_Key", value: fusion_bytesToBase64(Java.cast(z, iv_parameter_spec).getIV())}
                        ]);

                    } catch (err) {
                        try{
                            data = data.concat([
                                {key: "PBE_Salt", value: fusion_bytesToBase64(Java.cast(z, pbe_parameter_spec).getSalt())}
                            ]);
                        } catch (err) {
                            try{
                                gcm = Java.cast(z, gcm_parameter_spec)
                                data = data.concat([
                                    {key: "IV_Key", value: fusion_bytesToBase64(gcm.getIV())},
                                    {key: "Auth_Tag_Length", value: gcm.getTLen().toString()},
                                ]);
                            } catch (err) { }
                        }
                    }

                    fusion_sendKeyValueData("cipher.init", data);
                } catch (err1) {
                    fusion_sendError(err1)
                }
                this.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").call(this, opmode, key, algorithmParameter);
            }

            cipher.getInstance.overload("java.lang.String").implementation = function (arg0) {
                fusion_sendKeyValueData("cipher.getInstance", [
                    {key: "Algorithm", value: arg0}
                ]);
                return this.getInstance(arg0);
            };

            cipher.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("cipher.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

            cipher.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("cipher.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

            cipher.doFinal.overload("[B").implementation = function (arg0) {
                const inputBase64 = fusion_bytesToBase64(arg0);
                const output = this.doFinal.overload("[B").call(this, arg0);
                const outputBase64 = fusion_bytesToBase64(output);
                fusion_sendKeyValueData("cipher.doFinal", [
                    {key: "HashCode", value: this.hashCode().toString()},
                    {key: "Input", value: inputBase64},
                    {key: "Output", value: outputBase64}
                ]);
                return output;
            };

            cipher.doFinal.overload("[B", "int").implementation = function (arg0, arg1) {
                const inputBase64 = fusion_bytesToBase64(arg0);
                const output = this.doFinal.overload("[B", "int").call(this, arg0, arg1);
                const outputBase64 = fusion_bytesToBase64(output);
                fusion_sendKeyValueData("cipher.doFinal", [
                    {key: "HashCode", value: this.hashCode().toString()},
                    {key: "Input", value: inputBase64},
                    {key: "Output", value: outputBase64}
                ]);
                return output;
            }

            cipher.doFinal.overload("[B", "int", "int").implementation = function (arg0, arg1, arg2) {
                const inputBase64 = fusion_bytesToBase64(arg0);
                const output = this.doFinal.overload("[B", "int", "int").call(this, arg0, arg1, arg2);
                const outputBase64 = fusion_bytesToBase64(output);
                fusion_sendKeyValueData("cipher.doFinal", [
                    {key: "HashCode", value: this.hashCode().toString()},
                    {key: "Input", value: inputBase64},
                    {key: "Output", value: outputBase64}
                ]);
                return output;
            }

            cipher.doFinal.overload("[B", "int", "int", "[B").implementation = function (arg0, arg1, arg2, arg3) {
                const inputBase64 = fusion_bytesToBase64(arg0);
                const output = this.doFinal.overload("[B", "int", "int", "[B").call(this, arg0, arg1, arg2, arg3);
                const outputBase64 = fusion_bytesToBase64(output);
                fusion_sendKeyValueData("cipher.doFinal", [
                    {key: "HashCode", value: this.hashCode().toString()},
                    {key: "Input", value: inputBase64},
                    {key: "Output", value: outputBase64}
                ]);
                return output;
            }

            cipher.doFinal.overload("[B", "int", "int", "[B", "int").implementation = function (arg0, arg1, arg2, arg3, arg4) {
                const inputBase64 = fusion_bytesToBase64(arg0);
                const output = this.doFinal.overload("[B", "int", "int", "[B", "int").call(this, arg0, arg1, arg2, arg3, arg4);
                const outputBase64 = fusion_bytesToBase64(output);
                fusion_sendKeyValueData("cipher.doFinal", [
                    {key: "HashCode", value: this.hashCode().toString()},
                    {key: "Input", value: inputBase64},
                    {key: "Output", value: outputBase64}
                ]);
                return output;
            }
        }


        if (CRYPTO_MODULES.Mac) {
            fusion_sendMessage('*', "Module attached: javax.crypto.Mac");
            const mac = Java.use("javax.crypto.Mac");
            mac.getInstance.overload("java.lang.String").implementation = function (arg0) {
                fusion_sendKeyValueData("mac.getInstance", [
                    {key: "Algorithm", value: arg0}
                ]);
                return this.getInstance(arg0);
            };

            mac.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("mac.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };

            mac.getInstance.overload("java.lang.String", "java.security.Provider").implementation = function (arg0, arg1) {
                fusion_sendKeyValueData("mac.getInstance", [
                    {key: "Algorithm", value: arg0},
                    {key: "Provider", value: arg1}
                ]);
                return this.getInstance(arg0, arg1);
            };
        }

        if (CRYPTO_MODULES.KeyGenParameterSpec) {
            fusion_sendMessage('*', "Module attached: android.security.keystore.KeyGenParameterSpec$Builder");
            const useKeyGen = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
            useKeyGen.$init.overload("java.lang.String", "int").implementation = function (keyStoreAlias, purpose) {
                let purposeStr = "";
                if (purpose === 1) {
                    purposeStr = "encrypt";
                } else if (purpose === 2) {
                    purposeStr = "decrypt";
                } else if (purpose === 3) {
                    purposeStr = "decrypt|encrypt";
                } else if (purpose === 4) {
                    purposeStr = "sign";
                } else if (purpose === 8) {
                    purposeStr = "verify";
                } else {
                    purposeStr = purpose;
                }

                fusion_sendKeyValueData("KeyGenParameterSpec.init", [
                    {key: "KeyStoreAlias", value: keyStoreAlias},
                    {key: "Purpose", value: purposeStr}
                ]);
                return useKeyGen.$init.overload("java.lang.String", "int").call(this, keyStoreAlias, purpose);
            }

            useKeyGen.setBlockModes.implementation = function (modes) {
                fusion_sendKeyValueData("KeyGenParameterSpec.setBlockModes", [
                    {key: "BlockMode", value: modes.toString()}
                ]);
                return useKeyGen.setBlockModes.call(this, modes);
            }

            useKeyGen.setDigests.implementation = function (digests) {
                fusion_sendKeyValueData("KeyGenParameterSpec.setDigests", [
                    {key: "Digests", value: digests.toString()}
                ]);
                return useKeyGen.setDigests.call(this, digests);
            }

            useKeyGen.setKeySize.implementation = function (keySize) {
                fusion_sendKeyValueData("KeyGenParameterSpec.setKeySize", [
                    {key: "KeySize", value: keySize}
                ]);
                return useKeyGen.setKeySize.call(this, keySize);
            }

            useKeyGen.setEncryptionPaddings.implementation = function (paddings) {
                fusion_sendKeyValueData("KeyGenParameterSpec.setEncryptionPaddings", [
                    {key: "Paddings", value: paddings.toString()}
                ]);
                return useKeyGen.setEncryptionPaddings.call(this, paddings);
            }

            useKeyGen.setSignaturePaddings.implementation = function (paddings) {
                fusion_sendKeyValueData("KeyGenParameterSpec.setSignaturePaddings", [
                    {key: "Paddings", value: paddings.toString()}
                ]);
                return useKeyGen.setSignaturePaddings.call(this, paddings);
            }

            useKeyGen.setAlgorithmParameterSpec.implementation = function (spec) {
                fusion_sendKeyValueData("KeyGenParameterSpec.setAlgorithmParameterSpec", [
                    {key: "ParameterSpec", value: spec.toString()}
                ]);
                return useKeyGen.setAlgorithmParameterSpec.call(this, spec);
            }

            useKeyGen.build.implementation = function () {
                fusion_sendMessage('*', "KeyGenParameterSpec.build");
                return useKeyGen.build.call(this);
            }
        }

        if (CRYPTO_MODULES.IvParameterSpec) {
            fusion_sendMessage('*', "Module attached: javax.crypto.spec.IvParameterSpec");
            const ivParameter = Java.use("javax.crypto.spec.IvParameterSpec");
            ivParameter.$init.overload("[B").implementation = function (ivKey) {
                fusion_sendKeyValueData("IvParameterSpec.init", [
                    {key: "IV_Key", value: fusion_bytesToBase64(ivKey)},
                    {key: "ClassType", value: fusion_getClassName(this)}
                ]);
                return this.$init.overload("[B").call(this, ivKey);
            }

            ivParameter.$init.overload("[B", "int", "int").implementation = function (ivKey, offset, len) {
                fusion_sendKeyValueData("IvParameterSpec.init", [
                    {key: "IV Key", value: fusion_bytesToBase64(ivKey)},
                    {key: "Offset", value: offset},
                    {key: "Length", value: len},
                    {key: "ClassType", value: fusion_getClassName(this)}
                ]);
                return this.$init.overload("[B", "int", "int").call(this, ivKey, offset, len);
            }
        }

        if (CRYPTO_MODULES.GCMParameterSpec) {
            fusion_sendMessage('*', "Module attached: javax.crypto.spec.GCMParameterSpec");
            const gcmParameter = Java.use("javax.crypto.spec.GCMParameterSpec");
            gcmParameter.$init.overload("int", "[B").implementation = function (tLen, ivKey) {
                fusion_sendKeyValueData("GCMParameterSpec.init", [
                    {key: "IV_Key", value: fusion_bytesToBase64(ivKey)},
                    {key: "Auth_Tag_Length", value: tLen.toString()},
                    {key: "ClassType", value: fusion_getClassName(this)}
                ]);
                return this.$init.overload("int", "[B").call(this, tLen, ivKey);
            }

            gcmParameter.$init.overload("int", "[B", "int", "int").implementation = function (tLen, ivKey, offset, len) {
                fusion_sendKeyValueData("GCMParameterSpec.init", [
                    {key: "IV_Key", value: fusion_bytesToBase64(ivKey)},
                    {key: "Auth_Tag_Length", value: tLen.toString()},
                    {key: "Offset", value: offset},
                    {key: "Length", value: len},
                    {key: "ClassType", value: fusion_getClassName(this)}
                ]);
                return this.$init.overload("int", "[B", "int", "int").call(this, tLen, ivKey, offset, len);
            }
        }

        if (CRYPTO_MODULES.PBEParameterSpec) {
            fusion_sendMessage('*', "Module attached: javax.crypto.spec.PBEParameterSpec");
            const pbeParameter = Java.use("javax.crypto.spec.PBEParameterSpec");
            pbeParameter.$init.overload("[B", "int").implementation = function (salt, iterationCount) {
                fusion_sendKeyValueData("PBEParameterSpec.init", [
                    {key: "PBE_Salt", value: fusion_bytesToBase64(salt)},
                    {key: "Iteration_Count", value: iterationCount.toString()},
                    {key: "ClassType", value: fusion_getClassName(this)},
                ]);
                return this.$init.overload("[B", "int").call(this, salt, iterationCount);
            }

            pbeParameter.$init.overload("[B", "int", "java.security.spec.AlgorithmParameterSpec").implementation = function (salt, iterationCount, paramSpec) {
                
                var data = [
                    {key: "PBE_Salt", value: fusion_bytesToBase64(salt)},
                    {key: "Iteration_Count", value: iterationCount.toString()},
                    {key: "ClassType", value: fusion_getClassName(this)}
                    
                ]

                try{
                    data = data.concat([
                        {key: "Algorithm", value: paramSpec.getAlgorithm()},
                        {key: "ParamSpec", value: fusion_keyToBase64(paramSpec)},
                        {key: "ParamSpecType", value: fusion_getClassName(paramSpec)},
                        {key: "Provider", value: paramSpec.getProvider()}
                    ]);
                } catch (err) { }

                fusion_sendKeyValueData("PBEParameterSpec.init", data);
                return this.$init.overload("[B", "int", "java.security.spec.AlgorithmParameterSpec").call(this, salt, iterationCount, paramSpec);
            }
        }

        if (CRYPTO_MODULES.X509EncodedKeySpec) {
            fusion_sendMessage('*', "Module attached: java.security.spec.X509EncodedKeySpec");
            const x509EncodedKeySpec = Java.use("java.security.spec.X509EncodedKeySpec");
            x509EncodedKeySpec.$init.overload("[B").implementation = function (encodedKey) {
                fusion_sendKeyValueData("X509EncodedKeySpec.init", [
                    {key: "Key", value: fusion_bytesToBase64(encodedKey)},
                    {key: "ClassType", value: fusion_getClassName(this)}

                ]);
                return this.$init.overload("[B").call(this, encodedKey);
            }

        }

        fusion_sendMessage("W", "Crypto functions have been successfully initialized.")
    });
    
}, 0);

function fusion_keyToBase64(key){
    if (key === null || key === undefined) return "IA==";
    try{
        
        return fusion_bytesToBase64(key.getEncoded())

    } catch (err) {
        fusion_sendMessage("W", err);
        return "IA==";
    }
}
