/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
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
*/
using Sharpen;

namespace NSch
{
	public class SftpStatVFS
	{
		private long bsize;

		private long frsize;

		private long blocks;

		private long bfree;

		private long bavail;

		private long files;

		private long ffree;

		private long favail;

		private long fsid;

		private long flag;

		private long namemax;

		internal int flags = 0;

		internal long size;

		internal int uid;

		internal int gid;

		internal int permissions;

		internal int atime;

		internal int mtime;

		internal string[] extended = null;

		private SftpStatVFS()
		{
		}

  /*
   It seems data is serializsed according to sys/statvfs.h; for example,
   http://pubs.opengroup.org/onlinepubs/009604499/basedefs/sys/statvfs.h.html  
  */
		internal static NSch.SftpStatVFS getStatVFS(Buffer buf)
		{
			NSch.SftpStatVFS statvfs = new NSch.SftpStatVFS();
			statvfs.bsize = buf.GetLong();
			statvfs.frsize = buf.GetLong();
			statvfs.blocks = buf.GetLong();
			statvfs.bfree = buf.GetLong();
			statvfs.bavail = buf.GetLong();
			statvfs.files = buf.GetLong();
			statvfs.ffree = buf.GetLong();
			statvfs.favail = buf.GetLong();
			statvfs.fsid = buf.GetLong();
			int flag = (int)buf.GetLong();
			statvfs.namemax = buf.GetLong();
			statvfs.flag = (flag & 1) != 0 ? 1 : 0;
/*SSH2_FXE_STATVFS_ST_RDONLY*/
/*ST_RDONLY*/
			statvfs.flag |= (flag & 2) != 0 ? 2 : 0;
/*SSH2_FXE_STATVFS_ST_NOSUID*/
/*ST_NOSUID*/
			return statvfs;
		}

		public virtual long getBlockSize()
		{
			return bsize;
		}

		public virtual long getFragmentSize()
		{
			return frsize;
		}

		public virtual long getBlocks()
		{
			return blocks;
		}

		public virtual long getFreeBlocks()
		{
			return bfree;
		}

		public virtual long getAvailBlocks()
		{
			return bavail;
		}

		public virtual long getINodes()
		{
			return files;
		}

		public virtual long getFreeINodes()
		{
			return ffree;
		}

		public virtual long getAvailINodes()
		{
			return favail;
		}

		public virtual long getFileSystemID()
		{
			return fsid;
		}

		public virtual long getMountFlag()
		{
			return flag;
		}

		public virtual long getMaximumFilenameLength()
		{
			return namemax;
		}

		public virtual long getSize()
		{
			return getFragmentSize() * getBlocks() / 1024;
		}

		public virtual long getUsed()
		{
			return getFragmentSize() * (getBlocks() - getFreeBlocks()) / 1024;
		}

		public virtual long getAvailForNonRoot()
		{
			return getFragmentSize() * getAvailBlocks() / 1024;
		}

		public virtual long getAvail()
		{
			return getFragmentSize() * getFreeBlocks() / 1024;
		}

		public virtual int getCapacity()
		{
			return (int)(100 * (getBlocks() - getFreeBlocks()) / getBlocks());
		}
		//  public String toString() { return ""; }
	}
}
