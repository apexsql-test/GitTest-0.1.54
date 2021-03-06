// 
// Mac.cs
//  
// Author:
//       Lluis Sanchez Gual <lluis@novell.com>
// 
// Copyright (c) 2010 Novell, Inc (http://www.novell.com)
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using System.Security.Cryptography;
using System.IO;

namespace Sharpen
{
	public class Mac
	{
		MemoryStream ms = new MemoryStream ();
		HMAC mac;
		
		public static Mac GetInstance (string name)
		{
			Mac m = new Mac ();
			switch (name.ToUpper ()) {
			case "HMACMD5": m.mac = new HMACMD5 (); break;
			case "HMACSHA1": m.mac = new HMACSHA1 (); break;
			case "HMACSHA256": m.mac = new HMACSHA256(); break;
			}
			if (m.mac == null)
				throw new NotSupportedException ();
			return m;
		}
		
		public void Update (byte[] buf, int o, int l)
		{
			ms.Write (buf, o, l);
		}
		
		public void DoFinal(byte[] buf, int offset)
		{
			ms.Position = 0;
			byte[] hash = mac.ComputeHash (ms);
			hash.CopyTo (buf, offset);
			ms = new MemoryStream ();
		}
		
		public void Init (KeySpec key)
		{
			SecretKeySpec k = (SecretKeySpec) key;
			mac.Key = k.Key;
		}
	}
	
	
	internal class ShortBufferException: Exception
	{
	}
}

