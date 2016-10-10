/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2015-2016 ymnk, JCraft,Inc. All rights reserved.

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
using Sharpen;

namespace NSch
{
	public abstract class DHECN : KeyExchange
	{
		private const int SSH_MSG_KEX_ECDH_INIT = 30;

		private const int SSH_MSG_KEX_ECDH_REPLY = 31;

		private int state;

		internal byte[] Q_C;

		internal byte[] V_S;

		internal byte[] V_C;

		internal byte[] I_S;

		internal byte[] I_C;

		internal byte[] e;

		private Buffer buf;

		private Packet packet;

		private ECDH ecdh;

		protected internal string sha_name;

		protected internal int key_size;

		/// <exception cref="System.Exception"/>
		public override void Init(Session session, byte[] V_S, byte[] V_C, byte[] I_S, 
			byte[] I_C)
		{
			this.session = session;
			this.V_S = V_S;
			this.V_C = V_C;
			this.I_S = I_S;
			this.I_C = I_C;
			try
			{
				Type c = Sharpen.Runtime.GetType(session.GetConfig(sha_name));
				sha = (HASH)(System.Activator.CreateInstance(c));
				sha.Init();
			}
			catch (Exception e)
			{
				System.Console.Error.WriteLine(e);
			}
			buf = new Buffer();
			packet = new Packet(buf);
			packet.Reset();
			buf.PutByte(unchecked((byte)SSH_MSG_KEX_ECDH_INIT));
			try
			{
				Type c = Sharpen.Runtime.GetType(session.GetConfig("ecdh-sha2-nistp"));
				ecdh = (ECDH)(System.Activator.CreateInstance(c));
				ecdh.init(key_size);
				Q_C = ecdh.getQ();
				buf.PutString(Q_C);
			}
			catch (Exception e)
			{
				if (e is Exception)
				{
					throw new JSchException(e.ToString(), (Exception)e);
				}
				throw new JSchException(e.ToString());
			}
			if (V_S == null)
			{
				// This is a really ugly hack for Session.checkKexes ;-(
				return;
			}
			session.Write(packet);
			if (JSch.GetLogger().IsEnabled(Logger.INFO))
			{
				JSch.GetLogger().Log(Logger.INFO, "SSH_MSG_KEX_ECDH_INIT sent");
				JSch.GetLogger().Log(Logger.INFO, "expecting SSH_MSG_KEX_ECDH_REPLY");
			}
			state = SSH_MSG_KEX_ECDH_REPLY;
		}

		/// <exception cref="System.Exception"/>
		public override bool Next(Buffer _buf)
		{
			int i;
			int j;
			switch (state)
			{
				case SSH_MSG_KEX_ECDH_REPLY:
				{
					// The server responds with:
					// byte     SSH_MSG_KEX_ECDH_REPLY
					// string   K_S, server's public host key
					// string   Q_S, server's ephemeral public key octet string
					// string   the signature on the exchange hash
					j = _buf.GetInt();
					j = _buf.GetByte();
					j = _buf.GetByte();
					if (j != 31)
					{
						System.Console.Error.WriteLine("type: must be 31 " + j);
						return false;
					}
					K_S = _buf.GetString();
					byte[] Q_S = _buf.GetString();
					byte[][] r_s = KeyPairECDSA.fromPoint(Q_S);
					// RFC 5656,
					// 4. ECDH Key Exchange
					//   All elliptic curve public keys MUST be validated after they are
					//   received.  An example of a validation algorithm can be found in
					//   Section 3.2.2 of [SEC1].  If a key fails validation,
					//   the key exchange MUST fail.
					if (!ecdh.validate(r_s[0], r_s[1]))
					{
						return false;
					}
					K = ecdh.getSecret(r_s[0], r_s[1]);
					K = normalize(K);
					byte[] sig_of_H = _buf.GetString();
					//The hash H is computed as the HASH hash of the concatenation of the
					//following:
					// string   V_C, client's identification string (CR and LF excluded)
					// string   V_S, server's identification string (CR and LF excluded)
					// string   I_C, payload of the client's SSH_MSG_KEXINIT
					// string   I_S, payload of the server's SSH_MSG_KEXINIT
					// string   K_S, server's public host key
					// string   Q_C, client's ephemeral public key octet string
					// string   Q_S, server's ephemeral public key octet string
					// mpint    K,   shared secret
					// This value is called the exchange hash, and it is used to authenti-
					// cate the key exchange.
					buf.Reset();
					buf.PutString(V_C);
					buf.PutString(V_S);
					buf.PutString(I_C);
					buf.PutString(I_S);
					buf.PutString(K_S);
					buf.PutString(Q_C);
					buf.PutString(Q_S);
					buf.PutMPInt(K);
					byte[] foo = new byte[buf.GetLength()];
					buf.GetByte(foo);
					sha.Update(foo, 0, foo.Length);
					H = sha.Digest();
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
	}
}
