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
using Sharpen;

namespace NSch
{
/*
	public abstract class SignatureECDSA : Signature
	{
		/// <exception cref="System.Exception"/>
		public abstract void SetPubKey(byte[] r, byte[] s);

		/// <exception cref="System.Exception"/>
    public abstract void SetPrvKey(byte[] s);
	}
*/

	public interface SignatureECDSA
	{
		/// <exception cref="System.Exception"/>
		void Init();

		/// <exception cref="System.Exception"/>
		void SetPubKey(byte[] r, byte[] s);

		/// <exception cref="System.Exception"/>
		void SetPrvKey(byte[] s);

		/// <exception cref="System.Exception"/>
		void Update(byte[] H);

		/// <exception cref="System.Exception"/>
		bool Verify(byte[] sig);

		/// <exception cref="System.Exception"/>
		byte[] Sign();
	}
}