/*
Copyright (c) 2002-2016 ymnk, JCraft,Inc. All rights reserved.

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

This code is based on jsch (http://www.jcraft.com/jsch).
All credit should go to the authors of jsch.
*/

using System;
using NSch;
using Sharpen;

namespace NSch
{
	public abstract class KeyExchange
	{
		internal const int PROPOSAL_KEX_ALGS = 0;

		internal const int PROPOSAL_SERVER_HOST_KEY_ALGS = 1;

		internal const int PROPOSAL_ENC_ALGS_CTOS = 2;

		internal const int PROPOSAL_ENC_ALGS_STOC = 3;

		internal const int PROPOSAL_MAC_ALGS_CTOS = 4;

		internal const int PROPOSAL_MAC_ALGS_STOC = 5;

		internal const int PROPOSAL_COMP_ALGS_CTOS = 6;

		internal const int PROPOSAL_COMP_ALGS_STOC = 7;

		internal const int PROPOSAL_LANG_CTOS = 8;

		internal const int PROPOSAL_LANG_STOC = 9;

		internal const int PROPOSAL_MAX = 10;

		internal static string kex = "diffie-hellman-group1-sha1";

		internal static string server_host_key = "ssh-rsa,ssh-dss";

		internal static string enc_c2s = "blowfish-cbc";

		internal static string enc_s2c = "blowfish-cbc";

		internal static string mac_c2s = "hmac-md5";

		internal static string mac_s2c = "hmac-md5";

		internal static string lang_c2s = string.Empty;

		internal static string lang_s2c = string.Empty;

		public const int STATE_END = 0;

		protected internal Session session = null;

		protected internal HASH sha = null;

		protected internal byte[] K = null;

		protected internal byte[] H = null;

		protected internal byte[] K_S = null;

		//static String kex_algs="diffie-hellman-group-exchange-sha1"+
		//                       ",diffie-hellman-group1-sha1";
		//static String kex="diffie-hellman-group-exchange-sha1";
		// hmac-md5,hmac-sha1,hmac-ripemd160,
		// hmac-sha1-96,hmac-md5-96
		//static String comp_c2s="none";        // zlib
		//static String comp_s2c="none";
		/// <exception cref="System.Exception"/>
		public abstract void Init(Session session, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C);

		/// <exception cref="System.Exception"/>
		public abstract bool Next(Buffer buf);

		public abstract int GetState();

		protected internal readonly int RSA = 0;

		protected internal readonly int DSS = 1;

		protected internal readonly int ECDSA = 2;

		private int type = 0;

		private string key_alg_name = string.Empty;

		public virtual string GetKeyType()
		{
			if (type == DSS)
			{
				return "DSA";
			}
			if (type == RSA)
			{
				return "RSA";
			}
			return "ECDSA";
		}

		public virtual string getKeyAlgorithName()
		{
			return key_alg_name;
		}

		protected internal static string[] Guess(byte[] I_S, byte[] I_C)
		{
			string[] guess = new string[PROPOSAL_MAX];
			Buffer sb = new Buffer(I_S);
			sb.SetOffSet(17);
			Buffer cb = new Buffer(I_C);
			cb.SetOffSet(17);
			if (JSch.GetLogger().IsEnabled(Logger.INFO))
			{
				for (int i = 0; i < PROPOSAL_MAX; i++)
				{
					JSch.GetLogger().Log(Logger.INFO, "kex: server: " + Util.Byte2str(sb.GetString()));
				}
				for (int i_1 = 0; i_1 < PROPOSAL_MAX; i_1++)
				{
                    JSch.GetLogger().Log(Logger.INFO, "kex: client: " + Util.Byte2str(cb.GetString()));
				}
				sb.SetOffSet(17);
				cb.SetOffSet(17);
			}
			for (int i_2 = 0; i_2 < PROPOSAL_MAX; i_2++)
			{
				byte[] sp = sb.GetString();
				// server proposal
				byte[] cp = cb.GetString();
				// client proposal
				int j = 0;
				int k = 0;
				while (j < cp.Length)
				{
					while (j < cp.Length && cp[j] != ',')
					{
						j++;
					}
					if (k == j)
					{
						return null;
					}
					string algorithm = Util.Byte2str(cp, k, j - k);
					int l = 0;
					int m = 0;
					while (l < sp.Length)
					{
						while (l < sp.Length && sp[l] != ',')
						{
							l++;
						}
						if (m == l)
						{
							return null;
						}
						if (algorithm.Equals(Util.Byte2str(sp, m, l - m)))
						{
							guess[i_2] = algorithm;
							goto loop_break;
						}
						l++;
						m = l;
					}
					j++;
					k = j;
loop_continue: ;
				}
loop_break: ;
				if (j == 0)
				{
					guess[i_2] = string.Empty;
				}
				else
				{
					if (guess[i_2] == null)
					{
						return null;
					}
				}
			}
			if (JSch.GetLogger().IsEnabled(Logger.INFO))
			{
				JSch.GetLogger().Log(Logger.INFO, "kex: server->client" + " " + guess[PROPOSAL_ENC_ALGS_STOC
					] + " " + guess[PROPOSAL_MAC_ALGS_STOC] + " " + guess[PROPOSAL_COMP_ALGS_STOC]);
				JSch.GetLogger().Log(Logger.INFO, "kex: client->server" + " " + guess[PROPOSAL_ENC_ALGS_CTOS
					] + " " + guess[PROPOSAL_MAC_ALGS_CTOS] + " " + guess[PROPOSAL_COMP_ALGS_CTOS]);
			}
			return guess;
		}

		public virtual string GetFingerPrint()
		{
			HASH hash = null;
			try
			{
				Type c = Sharpen.Runtime.GetType(session.GetConfig("md5"));
				hash = (HASH)(System.Activator.CreateInstance(c));
			}
			catch (Exception e)
			{
				System.Console.Error.WriteLine("getFingerPrint: " + e);
			}
			return Util.GetFingerPrint(hash, GetHostKey());
		}

		internal virtual byte[] GetK()
		{
			return K;
		}

		internal virtual byte[] GetH()
		{
			return H;
		}

		internal virtual HASH GetHash()
		{
			return sha;
		}

		internal virtual byte[] GetHostKey()
		{
			return K_S;
		}

  /*
   * It seems JCE included in Oracle's Java7u6(and later) has suddenly changed
   * its behavior.  The secrete generated by KeyAgreement#generateSecret()
   * may start with 0, even if it is a positive value.
   */
		protected internal virtual byte[] normalize(byte[] secret)
		{
			if (secret.Length > 1 && secret[0] == 0 && (secret[1] & unchecked((int)(0x80))) ==
				 0)
			{
				byte[] tmp = new byte[secret.Length - 1];
				System.Array.Copy(secret, 1, tmp, 0, tmp.Length);
				return normalize(tmp);
			}
			else
			{
				return secret;
			}
		}

		/// <exception cref="System.Exception"/>
		protected internal virtual bool verify(string alg, byte[] K_S, int index, byte[]
			 sig_of_H)
		{
			int i;
			int j;
			i = index;
			bool result = false;
			if (alg.Equals("ssh-rsa"))
			{
				byte[] tmp;
				byte[] ee;
				byte[] n;
				type = RSA;
				key_alg_name = alg;
				j = ((K_S[i++] << 24) & unchecked((int)(0xff000000))) | ((K_S[i++] << 16) & unchecked(
					(int)(0x00ff0000))) | ((K_S[i++] << 8) & unchecked((int)(0x0000ff00))) | ((K_S[i
					++]) & unchecked((int)(0x000000ff)));
				tmp = new byte[j];
				System.Array.Copy(K_S, i, tmp, 0, j);
				i += j;
				ee = tmp;
				j = ((K_S[i++] << 24) & unchecked((int)(0xff000000))) | ((K_S[i++] << 16) & unchecked(
					(int)(0x00ff0000))) | ((K_S[i++] << 8) & unchecked((int)(0x0000ff00))) | ((K_S[i
					++]) & unchecked((int)(0x000000ff)));
				tmp = new byte[j];
				System.Array.Copy(K_S, i, tmp, 0, j);
				i += j;
				n = tmp;
				NSch.SignatureRSA sig = null;
				try
				{
					Type c = Sharpen.Runtime.GetType(session.GetConfig("signature.rsa"));
					sig = (NSch.SignatureRSA)(System.Activator.CreateInstance(c));
					sig.Init();
				}
				catch (Exception e)
				{
					System.Console.Error.WriteLine(e);
				}
				sig.SetPubKey(ee, n);
				sig.Update(H);
				result = sig.Verify(sig_of_H);
				if (JSch.GetLogger().IsEnabled(Logger.INFO))
				{
					JSch.GetLogger().Log(Logger.INFO, "ssh_rsa_verify: signature " + result);
				}
			}
			else
			{
				if (alg.Equals("ssh-dss"))
				{
					byte[] q = null;
					byte[] tmp;
					byte[] p;
					byte[] g;
					byte[] f;
					type = DSS;
					key_alg_name = alg;
					j = ((K_S[i++] << 24) & unchecked((int)(0xff000000))) | ((K_S[i++] << 16) & unchecked(
						(int)(0x00ff0000))) | ((K_S[i++] << 8) & unchecked((int)(0x0000ff00))) | ((K_S[i
						++]) & unchecked((int)(0x000000ff)));
					tmp = new byte[j];
					System.Array.Copy(K_S, i, tmp, 0, j);
					i += j;
					p = tmp;
					j = ((K_S[i++] << 24) & unchecked((int)(0xff000000))) | ((K_S[i++] << 16) & unchecked(
						(int)(0x00ff0000))) | ((K_S[i++] << 8) & unchecked((int)(0x0000ff00))) | ((K_S[i
						++]) & unchecked((int)(0x000000ff)));
					tmp = new byte[j];
					System.Array.Copy(K_S, i, tmp, 0, j);
					i += j;
					q = tmp;
					j = ((K_S[i++] << 24) & unchecked((int)(0xff000000))) | ((K_S[i++] << 16) & unchecked(
						(int)(0x00ff0000))) | ((K_S[i++] << 8) & unchecked((int)(0x0000ff00))) | ((K_S[i
						++]) & unchecked((int)(0x000000ff)));
					tmp = new byte[j];
					System.Array.Copy(K_S, i, tmp, 0, j);
					i += j;
					g = tmp;
					j = ((K_S[i++] << 24) & unchecked((int)(0xff000000))) | ((K_S[i++] << 16) & unchecked(
						(int)(0x00ff0000))) | ((K_S[i++] << 8) & unchecked((int)(0x0000ff00))) | ((K_S[i
						++]) & unchecked((int)(0x000000ff)));
					tmp = new byte[j];
					System.Array.Copy(K_S, i, tmp, 0, j);
					i += j;
					f = tmp;
					NSch.SignatureDSA sig = null;
					try
					{
						Type c = Sharpen.Runtime.GetType(session.GetConfig("signature.dss"));
						sig = (NSch.SignatureDSA)(System.Activator.CreateInstance(c));
						sig.Init();
					}
					catch (Exception e)
					{
						System.Console.Error.WriteLine(e);
					}
					sig.SetPubKey(f, p, q, g);
					sig.Update(H);
					result = sig.Verify(sig_of_H);
					if (JSch.GetLogger().IsEnabled(Logger.INFO))
					{
						JSch.GetLogger().Log(Logger.INFO, "ssh_dss_verify: signature " + result);
					}
				}
				else
				{
					if (alg.Equals("ecdsa-sha2-nistp256") || alg.Equals("ecdsa-sha2-nistp384") || alg
						.Equals("ecdsa-sha2-nistp521"))
					{
						byte[] tmp;
						byte[] r;
						byte[] s;
						// RFC 5656, 
						type = ECDSA;
						key_alg_name = alg;
						j = ((K_S[i++] << 24) & unchecked((int)(0xff000000))) | ((K_S[i++] << 16) & unchecked(
							(int)(0x00ff0000))) | ((K_S[i++] << 8) & unchecked((int)(0x0000ff00))) | ((K_S[i
							++]) & unchecked((int)(0x000000ff)));
						tmp = new byte[j];
						System.Array.Copy(K_S, i, tmp, 0, j);
						i += j;
						j = ((K_S[i++] << 24) & unchecked((int)(0xff000000))) | ((K_S[i++] << 16) & unchecked(
							(int)(0x00ff0000))) | ((K_S[i++] << 8) & unchecked((int)(0x0000ff00))) | ((K_S[i
							++]) & unchecked((int)(0x000000ff)));
						i++;
						tmp = new byte[(j - 1) / 2];
						System.Array.Copy(K_S, i, tmp, 0, tmp.Length);
						i += (j - 1) / 2;
						r = tmp;
						tmp = new byte[(j - 1) / 2];
						System.Array.Copy(K_S, i, tmp, 0, tmp.Length);
						i += (j - 1) / 2;
						s = tmp;
						SignatureECDSA sig = null;
						try
						{
							Type c = Sharpen.Runtime.GetType(session.GetConfig("signature.ecdsa"));
							sig = (SignatureECDSA)(System.Activator.CreateInstance(c));
							sig.Init();
						}
						catch (Exception e)
						{
							System.Console.Error.WriteLine(e);
						}
						sig.SetPubKey(r, s);
						sig.Update(H);
						result = sig.Verify(sig_of_H);
					}
					else
					{
						System.Console.Error.WriteLine("unknown alg");
					}
				}
			}
			return result;
		}
	}
}
