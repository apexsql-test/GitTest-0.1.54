/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2013-2016 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright 
     notice, this list of conditions and the following disclaimer in 
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
using System;
using System.Collections;
using Mono.Math;
using Sharpen;

namespace NSch
{
	public class KeyPairPKCS8 : NSch.KeyPair
	{
		private static readonly byte[] rsaEncryption = new byte[] { unchecked((byte)0x2a
			), unchecked((byte)0x86), unchecked((byte)0x48), unchecked((byte)0x86), unchecked(
			(byte)0xf7), unchecked((byte)0x0d), unchecked((byte)0x01), unchecked((byte)0x01
			), unchecked((byte)0x01) };

		private static readonly byte[] dsaEncryption = new byte[] { unchecked((byte)0x2a
			), unchecked((byte)0x86), unchecked((byte)0x48), unchecked((byte)0xce), unchecked(
			(byte)0x38), unchecked((byte)0x04), unchecked((byte)0x1) };

		private static readonly byte[] pbes2 = new byte[] { unchecked((byte)0x2a), unchecked(
			(byte)0x86), unchecked((byte)0x48), unchecked((byte)0x86), unchecked((byte)0xf7
			), unchecked((byte)0x0d), unchecked((byte)0x01), unchecked((byte)0x05), unchecked(
			(byte)0x0d) };

		private static readonly byte[] pbkdf2 = new byte[] { unchecked((byte)0x2a), unchecked(
			(byte)0x86), unchecked((byte)0x48), unchecked((byte)0x86), unchecked((byte)0xf7
			), unchecked((byte)0x0d), unchecked((byte)0x01), unchecked((byte)0x05), unchecked(
			(byte)0x0c) };

		private static readonly byte[] aes128cbc = new byte[] { unchecked((byte)0x60), 
			unchecked((byte)0x86), unchecked((byte)0x48), unchecked((byte)0x01), unchecked(
			(byte)0x65), unchecked((byte)0x03), unchecked((byte)0x04), unchecked((byte)0x01
			), unchecked((byte)0x02) };

		private static readonly byte[] aes192cbc = new byte[] { unchecked((byte)0x60), 
			unchecked((byte)0x86), unchecked((byte)0x48), unchecked((byte)0x01), unchecked(
			(byte)0x65), unchecked((byte)0x03), unchecked((byte)0x04), unchecked((byte)0x01
			), unchecked((byte)0x16) };

		private static readonly byte[] aes256cbc = new byte[] { unchecked((byte)0x60), 
			unchecked((byte)0x86), unchecked((byte)0x48), unchecked((byte)0x01), unchecked(
			(byte)0x65), unchecked((byte)0x03), unchecked((byte)0x04), unchecked((byte)0x01
			), unchecked((byte)0x2a) };

		private static readonly byte[] pbeWithMD5AndDESCBC = new byte[] { unchecked((byte
			)0x2a), unchecked((byte)0x86), unchecked((byte)0x48), unchecked((byte)0x86), 
			unchecked((byte)0xf7), unchecked((byte)0x0d), unchecked((byte)0x01), unchecked(
			(byte)0x05), unchecked((byte)0x03) };

		private NSch.KeyPair kpair = null;

		public KeyPairPKCS8(JSch jsch)
			: base(jsch)
		{
		}

		/// <exception cref="NSch.JSchException"/>
		internal override void Generate(int key_size)
		{
		}

		private static readonly byte[] begin = Util.Str2byte("-----BEGIN DSA PRIVATE KEY-----"
			);

		private static readonly byte[] end = Util.Str2byte("-----END DSA PRIVATE KEY-----"
			);

		internal override byte[] GetBegin()
		{
			return begin;
		}

		internal override byte[] GetEnd()
		{
			return end;
		}

		internal override byte[] GetPrivateKey()
		{
			return null;
		}

		internal override bool Parse(byte[] plain)
		{
    /* from RFC5208
      PrivateKeyInfo ::= SEQUENCE {
        version                   Version,
        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
        privateKey                PrivateKey,
        attributes           [0]  IMPLICIT Attributes OPTIONAL 
      }
      Version ::= INTEGER
      PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
      PrivateKey ::= OCTET STRING
      Attributes ::= SET OF Attribute
    }
    */
			try
			{
				ArrayList values = new ArrayList();
				NSch.KeyPair.ASN1[] contents = null;
				NSch.KeyPair.ASN1 asn1 = new NSch.KeyPair.ASN1(this, plain);
				contents = asn1.getContents();
				NSch.KeyPair.ASN1 privateKeyAlgorithm = contents[1];
				NSch.KeyPair.ASN1 privateKey = contents[2];
				contents = privateKeyAlgorithm.getContents();
				byte[] privateKeyAlgorithmID = contents[0].getContent();
				contents = contents[1].getContents();
				if (contents.Length > 0)
				{
					for (int i = 0; i < contents.Length; i++)
					{
						values.Add(contents[i].getContent());
					}
				}
				byte[] _data = privateKey.getContent();
				NSch.KeyPair _kpair = null;
				if (Util.Array_equals(privateKeyAlgorithmID, rsaEncryption))
				{
					_kpair = new KeyPairRSA(jsch);
					_kpair.copy(this);
					if (_kpair.Parse(_data))
					{
						kpair = _kpair;
					}
				}
				else
				{
					if (Util.Array_equals(privateKeyAlgorithmID, dsaEncryption))
					{
						asn1 = new NSch.KeyPair.ASN1(this, _data);
						if (values.Count == 0)
						{
							// embedded DSA parameters format
          /*
             SEQUENCE
               SEQUENCE
                 INTEGER    // P_array
                 INTEGER    // Q_array
                 INTEGER    // G_array
               INTEGER      // prv_array
          */
							contents = asn1.getContents();
							byte[] bar = contents[1].getContent();
							contents = contents[0].getContents();
							for (int i = 0; i < contents.Length; i++)
							{
								values.Add(contents[i].getContent());
							}
							values.Add(bar);
						}
						else
						{
          /*
             INTEGER      // prv_array
          */
							values.Add(asn1.getContent());
						}
						byte[] P_array = (byte[])values[0];
						byte[] Q_array = (byte[])values[1];
						byte[] G_array = (byte[])values[2];
						byte[] prv_array = (byte[])values[3];
						// Y = g^X mode p
						byte[] pub_array = (new BigInteger(G_array)).ModPow(new BigInteger(prv_array), new 
							BigInteger(P_array)).GetBytes();
						KeyPairDSA _key = new KeyPairDSA(jsch, P_array, Q_array, G_array, pub_array, prv_array
							);
						plain = _key.GetPrivateKey();
						_kpair = new KeyPairDSA(jsch);
						_kpair.copy(this);
						if (_kpair.Parse(plain))
						{
							kpair = _kpair;
						}
					}
				}
			}
			catch (NSch.KeyPair.ASN1Exception)
			{
				return false;
			}
			catch (Exception)
			{
				//System.err.println(e);
				return false;
			}
			return kpair != null;
		}

		public override byte[] GetPublicKeyBlob()
		{
			return kpair.GetPublicKeyBlob();
		}

		internal override byte[] GetKeyTypeName()
		{
			return kpair.GetKeyTypeName();
		}

		public override int GetKeyType()
		{
			return kpair.GetKeyType();
		}

		internal override int GetKeySize()
		{
			return kpair.GetKeySize();
		}

		public override byte[] GetSignature(byte[] data)
		{
			return kpair.GetSignature(data);
		}

		public override SignatureBase GetVerifier()
		{
			return kpair.GetVerifier();
		}

		/// <exception cref="NSch.JSchException"/>
		public override byte[] ForSSHAgent()
		{
			return kpair.ForSSHAgent();
		}

		public override bool Decrypt(byte[] _passphrase)
		{
			if (!IsEncrypted())
			{
				return true;
			}
			if (_passphrase == null)
			{
				return !IsEncrypted();
			}
    /*
      SEQUENCE
        SEQUENCE
          OBJECT            :PBES2
          SEQUENCE
            SEQUENCE
              OBJECT            :PBKDF2
              SEQUENCE
                OCTET STRING      [HEX DUMP]:E4E24ADC9C00BD4D
                INTEGER           :0800
            SEQUENCE
              OBJECT            :aes-128-cbc
              OCTET STRING      [HEX DUMP]:5B66E6B3BF03944C92317BC370CC3AD0
        OCTET STRING      [HEX DUMP]:

or

      SEQUENCE
        SEQUENCE
          OBJECT            :pbeWithMD5AndDES-CBC
          SEQUENCE
            OCTET STRING      [HEX DUMP]:DBF75ECB69E3C0FC
            INTEGER           :0800
        OCTET STRING      [HEX DUMP]
    */
			try
			{
				NSch.KeyPair.ASN1[] contents = null;
				NSch.KeyPair.ASN1 asn1 = new NSch.KeyPair.ASN1(this, data);
				contents = asn1.getContents();
				byte[] _data = contents[1].getContent();
				NSch.KeyPair.ASN1 pbes = contents[0];
				contents = pbes.getContents();
				byte[] pbesid = contents[0].getContent();
				NSch.KeyPair.ASN1 pbesparam = contents[1];
				byte[] salt = null;
				int iterations = 0;
				byte[] iv = null;
				byte[] encryptfuncid = null;
				if (Util.Array_equals(pbesid, pbes2))
				{
					contents = pbesparam.getContents();
					NSch.KeyPair.ASN1 pbkdf = contents[0];
					NSch.KeyPair.ASN1 encryptfunc = contents[1];
					contents = pbkdf.getContents();
					byte[] pbkdfid = contents[0].getContent();
					NSch.KeyPair.ASN1 pbkdffunc = contents[1];
					contents = pbkdffunc.getContents();
					salt = contents[0].getContent();
					iterations = System.Convert.ToInt32((new BigInteger(contents[1].getContent())).ToString
						());
					contents = encryptfunc.getContents();
					encryptfuncid = contents[0].getContent();
					iv = contents[1].getContent();
				}
				else
				{
					if (Util.Array_equals(pbesid, pbeWithMD5AndDESCBC))
					{
						// not supported
						return false;
					}
					else
					{
						return false;
					}
				}
				NSch.Cipher cipher = getCipher(encryptfuncid);
				if (cipher == null)
				{
					return false;
				}
				byte[] key = null;
				try
				{
					Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig("pbkdf"));
					PBKDF tmp = (PBKDF)(System.Activator.CreateInstance(c));
					key = tmp.getKey(_passphrase, salt, iterations, cipher.GetBlockSize());
				}
				catch (Exception)
				{
				}
				if (key == null)
				{
					return false;
				}
				cipher.Init(NSch.Cipher.DECRYPT_MODE, key, iv);
				Util.Bzero(key);
				byte[] plain = new byte[_data.Length];
				cipher.Update(_data, 0, _data.Length, plain, 0);
				if (Parse(plain))
				{
					encrypted = false;
					return true;
				}
			}
			catch (NSch.KeyPair.ASN1Exception)
			{
			}
			catch (Exception)
			{
			}
			// System.err.println(e);
			// System.err.println(e);
			return false;
		}

		internal virtual NSch.Cipher getCipher(byte[] id)
		{
			NSch.Cipher cipher = null;
			string name = null;
			try
			{
				if (Util.Array_equals(id, aes128cbc))
				{
					name = "aes128-cbc";
				}
				else
				{
					if (Util.Array_equals(id, aes192cbc))
					{
						name = "aes192-cbc";
					}
					else
					{
						if (Util.Array_equals(id, aes256cbc))
						{
							name = "aes256-cbc";
						}
					}
				}
				Type c = Sharpen.Runtime.GetType((string)JSch.GetConfig(name));
				cipher = (NSch.Cipher)(System.Activator.CreateInstance(c));
			}
			catch (Exception)
			{
				if (JSch.GetLogger().IsEnabled(Logger.FATAL))
				{
					string message = string.Empty;
					if (name == null)
					{
						message = "unknown oid: " + Util.toHex(id);
					}
					else
					{
						message = "function " + name + " is not supported";
					}
					JSch.GetLogger().Log(Logger.FATAL, "PKCS8: " + message);
				}
			}
			return cipher;
		}
	}
}
