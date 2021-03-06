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
using System.Collections;
using System.IO;
using NSch;
using Sharpen;

namespace NSch
{
	public abstract class Channel : Runnable
	{
		internal const int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;

		internal const int SSH_MSG_CHANNEL_OPEN_FAILURE = 92;

		internal const int SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;

		internal const int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;

		internal const int SSH_OPEN_CONNECT_FAILED = 2;

		internal const int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;

		internal const int SSH_OPEN_RESOURCE_SHORTAGE = 4;

		internal static int index = 0;

		private static ArrayList pool = new ArrayList();

		internal static NSch.Channel GetChannel(string type)
		{
			if (type.Equals("session"))
			{
				return new ChannelSession();
			}
			if (type.Equals("shell"))
			{
				return new ChannelShell();
			}
			if (type.Equals("exec"))
			{
				return new ChannelExec();
			}
			if (type.Equals("x11"))
			{
				return new ChannelX11();
			}
			if (type.Equals("auth-agent@openssh.com"))
			{
				return new ChannelAgentForwarding();
			}
			if (type.Equals("direct-tcpip"))
			{
				return new ChannelDirectTCPIP();
			}
			if (type.Equals("forwarded-tcpip"))
			{
				return new ChannelForwardedTCPIP();
			}
			if (type.Equals("sftp"))
			{
				return new ChannelSftp();
			}
			if (type.Equals("subsystem"))
			{
				return new ChannelSubsystem();
			}
			return null;
		}

		internal static NSch.Channel GetChannel(int id, Session session)
		{
			lock (pool)
			{
				for (int i = 0; i < pool.Count; i++)
				{
					NSch.Channel c = (NSch.Channel)(pool[i]);
					if (c.id == id && c.session == session)
					{
						return c;
					}
				}
			}
			return null;
		}

		internal static void Del(NSch.Channel c)
		{
			lock (pool)
			{
				pool.RemoveElement(c);
			}
		}

		internal int id;

		internal volatile int recipient = -1;

		protected internal byte[] type = Util.Str2byte("foo");

		internal volatile int lwsize_max = unchecked((int)(0x100000));

		internal volatile int lwsize;

		internal volatile int lmpsize = unchecked((int)(0x4000));

		internal long rwsize = 0;

		internal volatile int rmpsize = 0;

		internal IO io = null;

		internal Sharpen.Thread thread = null;

		internal volatile bool eof_local = false;

		internal volatile bool eof_remote = false;

		internal volatile bool close = false;

		internal volatile bool connected = false;

		internal volatile bool open_confirmation = false;

		internal volatile int exitstatus = -1;

		internal volatile int reply = 0;

		internal volatile int connectTimeout = 0;

		private Session session;

		internal int notifyme = 0;

		internal Channel()
		{
			lwsize = lwsize_max;
			// local initial window size
			// local maximum packet size
			// remote initial window size
			// remote maximum packet size
			lock (pool)
			{
				id = index++;
				pool.Add(this);
			}
		}

		internal virtual void SetRecipient(int foo)
		{
			lock (this)
			{
				this.recipient = foo;
				if (notifyme > 0)
				{
					Sharpen.Runtime.NotifyAll(this);
				}
			}
		}

		internal virtual int GetRecipient()
		{
			return recipient;
		}

		/// <exception cref="NSch.JSchException">
		internal virtual void Init()
		{
		}

		/// <exception cref="NSch.JSchException">
		public virtual void Connect()
		{
			Connect(0);
		}

		/// <exception cref="NSch.JSchException">
		public virtual void Connect(int connectTimeout)
		{
			this.connectTimeout = connectTimeout;
			try
			{
				SendChannelOpen();
				Start();
			}
			catch (Exception e)
			{
				connected = false;
				Disconnect();
				if (e is JSchException)
				{
					throw (JSchException)e;
				}
				throw new JSchException(e.ToString(), e);
			}
		}

		public virtual void SetXForwarding(bool foo)
		{
		}

		/// <exception cref="NSch.JSchException"/>
		public virtual void Start()
		{
		}

		public virtual bool IsEOF()
		{
			return eof_remote;
		}

		internal virtual void GetData(Buffer buf)
		{
			SetRecipient(buf.GetInt());
			SetRemoteWindowSize(buf.GetUInt());
			SetRemotePacketSize(buf.GetInt());
		}

		public virtual void SetInputStream(InputStream @in)
		{
			io.SetInputStream(@in, false);
		}

		public virtual void SetInputStream(InputStream @in, bool dontclose)
		{
			io.SetInputStream(@in, dontclose);
		}

		public virtual void SetOutputStream(OutputStream @out)
		{
			io.SetOutputStream(@out, false);
		}

		public virtual void SetOutputStream(OutputStream @out, bool dontclose)
		{
			io.SetOutputStream(@out, dontclose);
		}

		public virtual void SetExtOutputStream(OutputStream @out)
		{
			io.SetExtOutputStream(@out, false);
		}

		public virtual void SetExtOutputStream(OutputStream @out, bool dontclose)
		{
			io.SetExtOutputStream(@out, dontclose);
		}

		/// <exception cref="System.IO.IOException"/>
		public virtual InputStream GetInputStream()
		{
			int max_input_buffer_size = 32 * 1024;
			try
			{
				max_input_buffer_size = System.Convert.ToInt32(GetSession().GetConfig("max_input_buffer_size"));
			}
			catch (Exception)
			{
			}
			PipedInputStream @in = new Channel.MyPipedInputStream(this, 32 * 1024, max_input_buffer_size);
			// this value should be customizable.
			bool resizable = 32 * 1024 < max_input_buffer_size;
			io.SetOutputStream(new Channel.PassiveOutputStream(this, @in, resizable), false);
			return @in;
		}

		/// <exception cref="System.IO.IOException"/>
		public virtual InputStream GetExtInputStream()
		{
			int max_input_buffer_size = 32 * 1024;
			try
			{
				max_input_buffer_size = System.Convert.ToInt32(GetSession().GetConfig("max_input_buffer_size"));
			}
			catch (Exception)
			{
			}
			PipedInputStream @in = new Channel.MyPipedInputStream(this, 32 * 1024, max_input_buffer_size);
			// this value should be customizable.
			bool resizable = 32 * 1024 < max_input_buffer_size;
			io.SetExtOutputStream(new Channel.PassiveOutputStream(this, @in, resizable), false);
			return @in;
		}

		/// <exception cref="System.IO.IOException"/>
		public virtual OutputStream GetOutputStream()
		{
			NSch.Channel channel = this;
			OutputStream @out = new _OutputStream_229(this, channel);
			// close should be finished silently.
			return @out;
		}

		private sealed class _OutputStream_229 : OutputStream
		{
			public _OutputStream_229(Channel _enclosing, NSch.Channel channel)
			{
				this._enclosing = _enclosing;
				this.channel = channel;
				this.dataLen = 0;
				this.buffer = null;
				this.packet = null;
				this.closed = false;
				this.b = new byte[1];
			}

			private int dataLen;

			private Buffer buffer;

			private Packet packet;

			private bool closed;

			/// <exception cref="System.IO.IOException"/>
			private void Init()
			{
				lock (this)
				{
					this.buffer = new Buffer(this._enclosing.rmpsize);
					this.packet = new Packet(this.buffer);
					byte[] _buf = this.buffer.buffer;
					if (_buf.Length - (14 + 0) - Session.buffer_margin <= 0)
					{
						this.buffer = null;
						this.packet = null;
						throw new IOException("failed to initialize the channel.");
					}
				}
			}

			internal byte[] b;

			/// <exception cref="System.IO.IOException"/>
			public override void Write(int w)
			{
				this.b[0] = unchecked((byte)w);
				this.Write(this.b, 0, 1);
			}

			/// <exception cref="System.IO.IOException"/>
			public override void Write(byte[] buf, int s, int l)
			{
				if (this.packet == null)
				{
					this.Init();
				}
				if (this.closed)
				{
					throw new IOException("Already closed");
				}
				byte[] _buf = this.buffer.buffer;
				int _bufl = _buf.Length;
				while (l > 0)
				{
					int _l = l;
					if (l > _bufl - (14 + this.dataLen) - Session.buffer_margin)
					{
						_l = _bufl - (14 + this.dataLen) - Session.buffer_margin;
					}
					if (_l <= 0)
					{
						this.Flush();
						continue;
					}
					System.Array.Copy(buf, s, _buf, 14 + this.dataLen, _l);
					this.dataLen += _l;
					s += _l;
					l -= _l;
				}
			}

			/// <exception cref="System.IO.IOException"/>
			public override void Flush()
			{
				if (this.closed)
				{
					throw new IOException("Already closed");
				}
				if (this.dataLen == 0)
				{
					return;
				}
				this.packet.Reset();
				this.buffer.PutByte(unchecked((byte)Session.SSH_MSG_CHANNEL_DATA));
				this.buffer.PutInt(this._enclosing.recipient);
				this.buffer.PutInt(this.dataLen);
				this.buffer.Skip(this.dataLen);
				try
				{
					int foo = this.dataLen;
					this.dataLen = 0;
					lock (channel)
					{
						if (!channel.close)
						{
							this._enclosing.GetSession().Write(this.packet, channel, foo);
						}
					}
				}
				catch (Exception e)
				{
					this.Close();
					throw new IOException(e.ToString());
				}
			}

			/// <exception cref="System.IO.IOException"/>
			public override void Close()
			{
				if (this.packet == null)
				{
					try
					{
						this.Init();
					}
					catch (IOException)
					{
						return;
					}
				}
				if (this.closed)
				{
					return;
				}
				if (this.dataLen > 0)
				{
					this.Flush();
				}
				channel.Eof();
				this.closed = true;
			}

			private readonly Channel _enclosing;

			private readonly NSch.Channel channel;
		}

		internal class MyPipedInputStream : PipedInputStream
		{
			private int BufferSize = 1024;

			private int max_buffer_size = 1024;

			/// <exception cref="System.IO.IOException"/>
			internal MyPipedInputStream(Channel _enclosing): base()
			{
				this._enclosing = _enclosing;
			}

			/// <exception cref="System.IO.IOException"/>
			internal MyPipedInputStream(Channel _enclosing, int size): base()
			{
				this._enclosing = _enclosing;
				this.buffer = new byte[size];
				this.BufferSize = size;
				this.max_buffer_size = size;
			}

			/// <exception cref="System.IO.IOException"/>
            internal MyPipedInputStream(Channel _enclosing, int size, int max_buffer_size): base()
            {
                this._enclosing = _enclosing;
                this.BufferSize = size;
                this.max_buffer_size = max_buffer_size;
            }

			/// <exception cref="System.IO.IOException"/>
			internal MyPipedInputStream(Channel _enclosing, PipedOutputStream @out)
				: base(@out)
			{
				this._enclosing = _enclosing;
			}

			/// <exception cref="System.IO.IOException"/>
			internal MyPipedInputStream(Channel _enclosing, PipedOutputStream @out, int size)
				: base(@out)
			{
				this._enclosing = _enclosing;
				this.buffer = new byte[size];
				this.BufferSize = size;
			}

    /*
     * TODO: We should have our own Piped[I/O]Stream implementation.
     * Before accepting data, JDK's PipedInputStream will check the existence of
     * reader thread, and if it is not alive, the stream will be closed.
     * That behavior may cause the problem if multiple threads make access to it.
     */
			/// <exception cref="System.IO.IOException"/>
			public virtual void UpdateReadSide()
			{
				lock (this)
				{
					if (this.Available() != 0)
					{
						// not empty
						return;
					}
					this.@in = 0;
					this.@out = 0;
					this.buffer[this.@in++] = 0;
					this.Read();
				}
			}

			private int FreeSpace()
			{
				int size = 0;
				if (this.@out < this.@in)
				{
					size = this.buffer.Length - this.@in;
				}
				else
				{
					if (this.@in < this.@out)
					{
						if (this.@in == -1)
						{
							size = this.buffer.Length;
						}
						else
						{
							size = this.@out - this.@in;
						}
					}
				}
				return size;
			}

			/// <exception cref="System.IO.IOException"/>
			internal virtual void CheckSpace(int len)
			{
				lock (this)
				{
					int size = this.FreeSpace();
					if (size < len)
					{
						int datasize = this.buffer.Length - size;
						int foo = this.buffer.Length;
						while ((foo - datasize) < len)
						{
							foo *= 2;
						}
						if (foo > this.max_buffer_size)
						{
							foo = this.max_buffer_size;
						}
						if ((foo - datasize) < len)
						{
							return;
						}
						byte[] tmp = new byte[foo];
						if (this.@out < this.@in)
						{
							System.Array.Copy(this.buffer, 0, tmp, 0, this.buffer.Length);
						}
						else
						{
							if (this.@in < this.@out)
							{
								if (this.@in == -1)
								{
								}
								else
								{
									System.Array.Copy(this.buffer, 0, tmp, 0, this.@in);
									System.Array.Copy(this.buffer, this.@out, tmp, tmp.Length - (this.buffer.Length - this.@out), (this.buffer.Length - this.@out));
									this.@out = tmp.Length - (this.buffer.Length - this.@out);
								}
							}
							else
							{
								if (this.@in == this.@out)
								{
									System.Array.Copy(this.buffer, 0, tmp, 0, this.buffer.Length);
									this.@in = this.buffer.Length;
								}
							}
						}
						this.buffer = tmp;
					}
					else
					{
						if (this.buffer.Length == size && size > this.BufferSize)
						{
							int i = size / 2;
							if (i < this.BufferSize)
							{
								i = this.BufferSize;
							}
							byte[] tmp = new byte[i];
							this.buffer = tmp;
						}
					}
				}
			}

			private readonly Channel _enclosing;
		}

		internal virtual void SetLocalWindowSizeMax(int foo)
		{
			this.lwsize_max = foo;
		}

		internal virtual void SetLocalWindowSize(int foo)
		{
			this.lwsize = foo;
		}

		internal virtual void SetLocalPacketSize(int foo)
		{
			this.lmpsize = foo;
		}

		internal virtual void SetRemoteWindowSize(long foo)
		{
			lock (this)
			{
				this.rwsize = foo;
			}
		}

		internal virtual void AddRemoteWindowSize(int foo)
		{
			lock (this)
			{
				this.rwsize += foo;
				if (notifyme > 0)
				{
					Sharpen.Runtime.NotifyAll(this);
				}
			}
		}

		internal virtual void SetRemotePacketSize(int foo)
		{
			this.rmpsize = foo;
		}

		public virtual void Run()
		{
		}

		/// <exception cref="System.IO.IOException"/>
		internal virtual void Write(byte[] foo)
		{
			Write(foo, 0, foo.Length);
		}

		/// <exception cref="System.IO.IOException"/>
		internal virtual void Write(byte[] foo, int s, int l)
		{
			try
			{
				io.Put(foo, s, l);
			}
			catch (ArgumentNullException)
			{
			}
		}

		/// <exception cref="System.IO.IOException"/>
		internal virtual void Write_ext(byte[] foo, int s, int l)
		{
			try
			{
				io.Put_ext(foo, s, l);
			}
			catch (ArgumentNullException)
			{
			}
		}

		internal virtual void Eof_remote()
		{
			eof_remote = true;
			try
			{
				io.Out_close();
			}
			catch (ArgumentNullException)
			{
			}
		}

		internal virtual void Eof()
		{
			if (eof_local)
			{
				return;
			}
			eof_local = true;
			int i = GetRecipient();
			if (i == -1)
			{
				return;
			}
			try
			{
				Buffer buf = new Buffer(100);
				Packet packet = new Packet(buf);
				packet.Reset();
				buf.PutByte(unchecked((byte)Session.SSH_MSG_CHANNEL_EOF));
				buf.PutInt(i);
				lock (this)
				{
					if (!close)
					{
						GetSession().Write(packet);
					}
				}
			}
			catch (Exception)
			{
			}
		}

		//System.err.println("Channel.eof");
		//e.printStackTrace();
    /*
    if(!isConnected()){ disconnect(); }
    */
  /*
  http://www1.ietf.org/internet-drafts/draft-ietf-secsh-connect-24.txt

5.3  Closing a Channel
  When a party will no longer send more data to a channel, it SHOULD
   send SSH_MSG_CHANNEL_EOF.

            byte      SSH_MSG_CHANNEL_EOF
            uint32    recipient_channel

  No explicit response is sent to this message.  However, the
   application may send EOF to whatever is at the other end of the
  channel.  Note that the channel remains open after this message, and
   more data may still be sent in the other direction.  This message
   does not consume window space and can be sent even if no window space
   is available.

     When either party wishes to terminate the channel, it sends
     SSH_MSG_CHANNEL_CLOSE.  Upon receiving this message, a party MUST
   send back a SSH_MSG_CHANNEL_CLOSE unless it has already sent this
   message for the channel.  The channel is considered closed for a
     party when it has both sent and received SSH_MSG_CHANNEL_CLOSE, and
   the party may then reuse the channel number.  A party MAY send
   SSH_MSG_CHANNEL_CLOSE without having sent or received
   SSH_MSG_CHANNEL_EOF.

            byte      SSH_MSG_CHANNEL_CLOSE
            uint32    recipient_channel

   This message does not consume window space and can be sent even if no
   window space is available.

   It is recommended that any data sent before this message is delivered
     to the actual destination, if possible.
  */
		internal virtual void Close()
		{
			if (close)
			{
				return;
			}
			close = true;
			eof_local = eof_remote = true;
			int i = GetRecipient();
			if (i == -1)
			{
				return;
			}
			try
			{
				Buffer buf = new Buffer(100);
				Packet packet = new Packet(buf);
				packet.Reset();
				buf.PutByte(unchecked((byte)Session.SSH_MSG_CHANNEL_CLOSE));
				buf.PutInt(i);
				lock (this)
				{
					GetSession().Write(packet);
				}
			}
			catch (Exception)
			{
			}
		}

		//e.printStackTrace();
		public virtual bool IsClosed()
		{
			return close;
		}

		internal static void Disconnect(Session session)
		{
			Channel[] channels = null;
			int count = 0;
			lock (pool)
			{
				channels = new Channel[pool.Count];
				for (int i = 0; i < pool.Count; i++)
				{
					try
					{
						Channel c = ((Channel)(pool[i]));
						if (c.session == session)
						{
							channels[count++] = c;
						}
					}
					catch (Exception)
					{
					}
				}
			}
			for (int i_1 = 0; i_1 < count; i_1++)
			{
				channels[i_1].Disconnect();
			}
		}

		public virtual void Disconnect()
		{
			//System.err.println(this+":disconnect "+io+" "+connected);
			//Thread.dumpStack();
			try
			{
				lock (this)
				{
					if (!connected)
					{
						return;
					}
					connected = false;
				}
				Close();
				eof_remote = eof_local = true;
				thread = null;
				try
				{
					if (io != null)
					{
						io.Close();
					}
				}
				catch (Exception)
				{
				}
			}
			finally
			{
				//e.printStackTrace();
				// io=null;
				Channel.Del(this);
			}
		}

		public virtual bool IsConnected()
		{
			Session _session = this.session;
			if (_session != null)
			{
				return _session.IsConnected() && connected;
			}
			return false;
		}

		/// <exception cref="System.Exception"/>
		public virtual void SendSignal(string signal)
		{
			RequestSignal request = new RequestSignal();
			request.SetSignal(signal);
			request.DoRequest(GetSession(), this);
		}

		internal class PassiveInputStream : Channel.MyPipedInputStream
		{
			internal PipedOutputStream @out;

			/// <exception cref="System.IO.IOException"/>
			internal PassiveInputStream(Channel _enclosing, PipedOutputStream @out, int size)
				: base(_enclosing)
			{
				this._enclosing = _enclosing;
				//  public String toString(){
				//      return "Channel: type="+new String(type)+",id="+id+",recipient="+recipient+",window_size="+window_size+",packet_size="+packet_size;
				//  }
/*
  class OutputThread extends Thread{
    Channel c;
    OutputThread(Channel c){ this.c=c;}
    public void run(){c.output_thread();}
  }
*/
				this.@out = @out;
			}

			/// <exception cref="System.IO.IOException"/>
			internal PassiveInputStream(Channel _enclosing, PipedOutputStream @out)
				: base(_enclosing)
			{
				this._enclosing = _enclosing;
				this.@out = @out;
			}

			/// <exception cref="System.IO.IOException"/>
			public override void Close()
			{
				if (this.@out != null)
				{
					this.@out.Close();
				}
				this.@out = null;
			}

			private readonly Channel _enclosing;
		}

		internal class PassiveOutputStream : PipedOutputStream
		{
			private Channel.MyPipedInputStream _sink = null;

			/// <exception cref="System.IO.IOException"/>
			internal PassiveOutputStream(Channel _enclosing, PipedInputStream @in, bool resizable_buffer)
				: base(@in)
			{
				this._enclosing = _enclosing;
				if (resizable_buffer && (@in is Channel.MyPipedInputStream))
				{
					this._sink = (Channel.MyPipedInputStream)@in;
				}
			}

			/// <exception cref="System.IO.IOException"/>
			public override void Write(int b)
			{
				if (this._sink != null)
				{
					this._sink.CheckSpace(1);
				}
				base.Write(b);
			}

			/// <exception cref="System.IO.IOException"/>
			public override void Write(byte[] b, int off, int len)
			{
				if (this._sink != null)
				{
					this._sink.CheckSpace(len);
				}
				base.Write(b, off, len);
			}

			private readonly Channel _enclosing;
		}

		internal virtual void SetExitStatus(int status)
		{
			exitstatus = status;
		}

		public virtual int GetExitStatus()
		{
			return exitstatus;
		}

		internal virtual void SetSession(Session session)
		{
			this.session = session;
		}

		/// <exception cref="NSch.JSchException"/>
		public virtual Session GetSession()
		{
			Session _session = session;
			if (_session == null)
			{
				throw new JSchException("session is not available");
			}
			return _session;
		}

		public virtual int GetId()
		{
			return id;
		}

		/// <exception cref="System.Exception"/>
		protected internal virtual void SendOpenConfirmation()
		{
			Buffer buf = new Buffer(100);
			Packet packet = new Packet(buf);
			packet.Reset();
			buf.PutByte(unchecked((byte)SSH_MSG_CHANNEL_OPEN_CONFIRMATION));
			buf.PutInt(GetRecipient());
			buf.PutInt(id);
			buf.PutInt(lwsize);
			buf.PutInt(lmpsize);
			GetSession().Write(packet);
		}

		protected internal virtual void SendOpenFailure(int reasoncode)
		{
			try
			{
				Buffer buf = new Buffer(100);
				Packet packet = new Packet(buf);
				packet.Reset();
				buf.PutByte(unchecked((byte)SSH_MSG_CHANNEL_OPEN_FAILURE));
				buf.PutInt(GetRecipient());
				buf.PutInt(reasoncode);
				buf.PutString(Util.Str2byte("open failed"));
				buf.PutString(Util.empty);
				GetSession().Write(packet);
			}
			catch (Exception)
			{
			}
		}

		protected internal virtual Packet GenChannelOpenPacket()
		{
			Buffer buf = new Buffer(100);
			Packet packet = new Packet(buf);
			// byte   SSH_MSG_CHANNEL_OPEN(90)
			// string channel type         //
			// uint32 sender channel       // 0
			// uint32 initial window size  // 0x100000(65536)
			// uint32 maxmum packet size   // 0x4000(16384)
			packet.Reset();
			buf.PutByte(unchecked((byte)90));
			buf.PutString(this.type);
			buf.PutInt(this.id);
			buf.PutInt(this.lwsize);
			buf.PutInt(this.lmpsize);
			return packet;
		}

		/// <exception cref="System.Exception"/>
		protected internal virtual void SendChannelOpen()
		{
			Session _session = GetSession();
			if (!_session.IsConnected())
			{
				throw new JSchException("session is down");
			}
			Packet packet = GenChannelOpenPacket();
			_session.Write(packet);
			int retry = 2000;
			long start = Runtime.CurrentTimeMillis();
			long timeout = connectTimeout;
			if (timeout != 0L)
			{
				retry = 1;
			}
			lock (this)
			{
				while (this.GetRecipient() == -1 && _session.IsConnected() && retry > 0)
				{
					if (timeout > 0L)
					{
						if ((Runtime.CurrentTimeMillis() - start) > timeout)
						{
							retry = 0;
							continue;
						}
					}
					try
					{
						long t = timeout == 0L ? 10L : timeout;
						this.notifyme = 1;
						Sharpen.Runtime.Wait(this, t);
					}
					catch (Exception)
					{
					}
					finally
					{
						this.notifyme = 0;
					}
					retry--;
				}
			}
			if (!_session.IsConnected())
			{
				throw new JSchException("session is down");
			}
			if (this.GetRecipient() == -1)
			{
				// timeout
				throw new JSchException("channel is not opened.");
			}
			if (this.open_confirmation == false)
			{
				// SSH_MSG_CHANNEL_OPEN_FAILURE
				throw new JSchException("channel is not opened.");
			}
			connected = true;
		}
	}
}
