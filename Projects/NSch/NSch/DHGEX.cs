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
	public class DHGEX : KeyExchange
	{
		private const int SSH_MSG_KEX_DH_GEX_GROUP = 31;

		private const int SSH_MSG_KEX_DH_GEX_INIT = 32;

		private const int SSH_MSG_KEX_DH_GEX_REPLY = 33;

		private const int SSH_MSG_KEX_DH_GEX_REQUEST = 34;

		internal static int min = 1024;

		internal static int preferred = 1024;

		internal static int max = 1024;

		private int state;

		internal NSch.DH dh;

		internal byte[] V_S;

		internal byte[] V_C;

		internal byte[] I_S;

		internal byte[] I_C;

		private Buffer buf;

		private Packet packet;

		private byte[] p;

		private byte[] g;

		private byte[] e;

		protected internal string hash = "sha-1";

		/// <exception cref="System.Exception"/>
		public override void Init(Session session, byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C)
		{
			this.session = session;
			this.V_S = V_S;
			this.V_C = V_C;
			this.I_S = I_S;
			this.I_C = I_C;
			try
			{
				Type c = Sharpen.Runtime.GetType(session.GetConfig(hash));
				sha = (HASH)(System.Activator.CreateInstance(c));
				sha.Init();
			}
			catch (Exception e)
			{
				System.Console.Error.WriteLine(e);
			}
			buf = new Buffer();
			packet = new Packet(buf);
			try
			{
				Type c = Sharpen.Runtime.GetType(session.GetConfig("dh"));
				// Since JDK8, SunJCE has lifted the keysize restrictions
				// from 1024 to 2048 for DH.
				preferred = max = check2048(c, max);
				dh = (NSch.DH)(System.Activator.CreateInstance(c));
				dh.Init();
			}
			catch (Exception e)
			{
				throw;
			}
			packet.Reset();
			buf.PutByte(unchecked((byte)SSH_MSG_KEX_DH_GEX_REQUEST));
			buf.PutInt(min);
			buf.PutInt(preferred);
			buf.PutInt(max);
			session.Write(packet);
			if (JSch.GetLogger().IsEnabled(Logger.INFO))
			{
				JSch.GetLogger().Log(Logger.INFO, "SSH_MSG_KEX_DH_GEX_REQUEST(" + min + "<" + preferred + "<" + max + ") sent");
				JSch.GetLogger().Log(Logger.INFO, "expecting SSH_MSG_KEX_DH_GEX_GROUP");
			}
			state = SSH_MSG_KEX_DH_GEX_GROUP;
		}

		/// <exception cref="System.Exception"/>
		public override bool Next(Buffer _buf)
		{
			int i;
			int j;
			switch (state)
			{
				case SSH_MSG_KEX_DH_GEX_GROUP:
				{
					// byte  SSH_MSG_KEX_DH_GEX_GROUP(31)
					// mpint p, safe prime
					// mpint g, generator for subgroup in GF (p)
					_buf.GetInt();
					_buf.GetByte();
					j = _buf.GetByte();
					if (j != SSH_MSG_KEX_DH_GEX_GROUP)
					{
						System.Console.Error.WriteLine("type: must be SSH_MSG_KEX_DH_GEX_GROUP " + j);
						return false;
					}
					p = _buf.GetMPInt();
					g = _buf.GetMPInt();
					dh.SetP(p);
					dh.SetG(g);
					// The client responds with:
					// byte  SSH_MSG_KEX_DH_GEX_INIT(32)
					// mpint e <- g^x mod p
					//         x is a random number (1 < x < (p-1)/2)
					e = dh.GetE();
					packet.Reset();
					buf.PutByte(unchecked((byte)SSH_MSG_KEX_DH_GEX_INIT));
					buf.PutMPInt(e);
					session.Write(packet);
					if (JSch.GetLogger().IsEnabled(Logger.INFO))
					{
						JSch.GetLogger().Log(Logger.INFO, "SSH_MSG_KEX_DH_GEX_INIT sent");
						JSch.GetLogger().Log(Logger.INFO, "expecting SSH_MSG_KEX_DH_GEX_REPLY");
					}
					state = SSH_MSG_KEX_DH_GEX_REPLY;
					return true;
				}

				case SSH_MSG_KEX_DH_GEX_REPLY:
				{
					//break;
					// The server responds with:
					// byte      SSH_MSG_KEX_DH_GEX_REPLY(33)
					// string    server public host key and certificates (K_S)
					// mpint     f
					// string    signature of H
					j = _buf.GetInt();
					j = _buf.GetByte();
					j = _buf.GetByte();
					if (j != SSH_MSG_KEX_DH_GEX_REPLY)
					{
						System.Console.Error.WriteLine("type: must be SSH_MSG_KEX_DH_GEX_REPLY " + j);
						return false;
					}
					K_S = _buf.GetString();
					byte[] f = _buf.GetMPInt();
					byte[] sig_of_H = _buf.GetString();
					dh.SetF(f);
					dh.CheckRange();
					K = normalize(dh.GetK());
					//The hash H is computed as the HASH hash of the concatenation of the
					//following:
					// string    V_C, the client's version string (CR and NL excluded)
					// string    V_S, the server's version string (CR and NL excluded)
					// string    I_C, the payload of the client's SSH_MSG_KEXINIT
					// string    I_S, the payload of the server's SSH_MSG_KEXINIT
					// string    K_S, the host key
					// uint32    min, minimal size in bits of an acceptable group
					// uint32   n, preferred size in bits of the group the server should send
					// uint32    max, maximal size in bits of an acceptable group
					// mpint     p, safe prime
					// mpint     g, generator for subgroup
					// mpint     e, exchange value sent by the client
					// mpint     f, exchange value sent by the server
					// mpint     K, the shared secret
					// This value is called the exchange hash, and it is used to authenti-
					// cate the key exchange.
					buf.Reset();
					buf.PutString(V_C);
					buf.PutString(V_S);
					buf.PutString(I_C);
					buf.PutString(I_S);
					buf.PutString(K_S);
					buf.PutInt(min);
					buf.PutInt(preferred);
					buf.PutInt(max);
					buf.PutMPInt(p);
					buf.PutMPInt(g);
					buf.PutMPInt(e);
					buf.PutMPInt(f);
					buf.PutMPInt(K);
					byte[] foo = new byte[buf.GetLength()];
					buf.GetByte(foo);
					sha.Update(foo, 0, foo.Length);
					H = sha.Digest();
					// System.err.print("H -> "); dump(H, 0, H.length);
					i = 0;
					j = 0;
					j = ((K_S[i++] << 24) & unchecked((int)(0xff000000))) | ((K_S[i++] << 16) & unchecked(
						(int)(0x00ff0000))) | ((K_S[i++] << 8) & unchecked((int)(0x0000ff00))) | ((K_S[i
						++]) & unchecked((int)(0x000000ff)));
					string alg = Util.Byte2str(K_S, i, j);
					i += j;
					bool result = verify(alg, K_S, i, sig_of_H);
					state = STATE_END;
					return result;
				}
			}
			return false;
		}

		public override int GetState()
		{
			return state;
		}

		/// <exception cref="System.Exception"/>
		protected internal virtual int check2048(Type c, int _max)
		{
			NSch.DH dh = (NSch.DH)(System.Activator.CreateInstance(c));
			dh.Init();
			byte[] foo = new byte[257];
			foo[1] = unchecked((byte)0xdd);
			foo[256] = unchecked((int)(0x73));
			dh.SetP(foo);
			byte[] bar = new byte[] { unchecked((byte)0x02) };
			dh.SetG(bar);
			try
			{
				dh.GetE();
				_max = 2048;
			}
			catch (Exception)
			{
			}
			return _max;
		}
	}
}
