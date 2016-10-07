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
	public class HostKey
	{
		private static readonly byte[][] names = new byte[][] { Util.Str2byte("ssh-dss"
			), Util.Str2byte("ssh-rsa"), Util.Str2byte("ecdsa-sha2-nistp256"), Util.Str2byte
			("ecdsa-sha2-nistp384"), Util.Str2byte("ecdsa-sha2-nistp521") };

		protected internal const int GUESS = 0;

		public const int SSHDSS = 1;

		public const int SSHRSA = 2;

		public const int ECDSA256 = 3;

		public const int ECDSA384 = 4;

		public const int ECDSA521 = 5;

		internal const int UNKNOWN = 6;

		protected internal string marker;

		protected internal string host;

		protected internal int type;

		protected internal byte[] key;

		protected internal string comment;

		/// <exception cref="NSch.JSchException"/>
		public HostKey(string host, byte[] key) : this(host, GUESS, key)
		{
		}

		/// <exception cref="NSch.JSchException"/>
		public HostKey(string host, int type, byte[] key)
			: this(host, type, key, null)
		{
		}

		/// <exception cref="NSch.JSchException"/>
		public HostKey(string host, int type, byte[] key, string comment)
			: this(string.Empty, host, type, key, comment)
		{
		}

		/// <exception cref="NSch.JSchException"/>
		public HostKey(string marker, string host, int type, byte[] key, string comment)
		{
			this.marker = marker;
			this.host = host;
			if (type == GUESS)
			{
				if (key[8] == 'd')
				{
					this.type = SSHDSS;
				}
				else
				{
					if (key[8] == 'r')
					{
						this.type = SSHRSA;
					}
					else
					{
						if (key[8] == 'a' && key[20] == '2')
						{
							this.type = ECDSA256;
						}
						else
						{
							if (key[8] == 'a' && key[20] == '3')
							{
								this.type = ECDSA384;
							}
							else
							{
								if (key[8] == 'a' && key[20] == '5')
								{
									this.type = ECDSA521;
								}
								else
								{
									throw new JSchException("invalid key type");
								}
							}
						}
					}
				}
			}
			else
			{
				this.type = type;
			}
			this.key = key;
			this.comment = comment;
		}

		public virtual string GetHost()
		{
			return host;
		}

		public virtual string GetType()
		{
			if (type == SSHDSS || type == SSHRSA || type == ECDSA256 || type == ECDSA384 || type
				 == ECDSA521)
			{
				return Util.Byte2str(names[type - 1]);
			}
			return "UNKNOWN";
		}

		protected internal static int name2type(string name)
		{
			for (int i = 0; i < names.Length; i++)
			{
				if (Util.Byte2str(names[i]).Equals(name))
				{
					return i + 1;
				}
			}
			return UNKNOWN;
		}

		public virtual string GetKey()
		{
			return Util.Byte2str(Util.ToBase64(key, 0, key.Length));
		}

		public virtual string GetFingerPrint(JSch jsch)
		{
			HASH hash = null;
			try
			{
				Type c = Sharpen.Runtime.GetType(JSch.GetConfig("md5"));
				hash = (HASH)(System.Activator.CreateInstance(c));
			}
			catch (Exception e)
			{
				System.Console.Error.WriteLine("getFingerPrint: " + e);
			}
			return Util.GetFingerPrint(hash, key);
		}

		public virtual string getComment()
		{
			return comment;
		}

		public virtual string getMarker()
		{
			return marker;
		}

		internal virtual bool IsMatched(string _host)
		{
			return IsIncluded(_host);
		}

		private bool IsIncluded(string _host)
		{
			int i = 0;
			string hosts = this.host;
			int hostslen = hosts.Length;
			int hostlen = _host.Length;
			int j;
			while (i < hostslen)
			{
				j = hosts.IndexOf(',', i);
				if (j == -1)
				{
					if (hostlen != hostslen - i)
					{
						return false;
					}
					return hosts.RegionMatches(true, i, _host, 0, hostlen);
				}
				if (hostlen == (j - i))
				{
					if (hosts.RegionMatches(true, i, _host, 0, hostlen))
					{
						return true;
					}
				}
				i = j + 1;
			}
			return false;
		}
	}
}
