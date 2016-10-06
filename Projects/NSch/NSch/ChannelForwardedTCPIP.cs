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
using System.Net.Sockets;
using NSch;
using Sharpen;

namespace NSch
{
	public class ChannelForwardedTCPIP : Channel
	{
		private static ArrayList pool = new ArrayList();

		private const int LOCAL_WINDOW_SIZE_MAX = unchecked((int)(0x20000));

		private const int LOCAL_MAXIMUM_PACKET_SIZE = unchecked((int)(0x4000));

		private const int TIMEOUT = 10 * 1000;

		private Socket socket = null;

		private ForwardedTCPIPDaemon daemon = null;

		private ChannelForwardedTCPIP.Config config = null;

		internal ChannelForwardedTCPIP()
			: base()
		{
			//static private final int LOCAL_WINDOW_SIZE_MAX=0x100000;
			SetLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
			SetLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
			SetLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
			io = new IO();
			connected = true;
		}

		public override void Run()
		{
			try
			{
				if (config is ChannelForwardedTCPIP.ConfigDaemon)
				{
					ChannelForwardedTCPIP.ConfigDaemon _config = (ChannelForwardedTCPIP.ConfigDaemon)config;
					Type c = Sharpen.Runtime.GetType(_config.target);
					daemon = (ForwardedTCPIPDaemon)System.Activator.CreateInstance(c);
					PipedOutputStream @out = new PipedOutputStream();
					io.SetInputStream(new Channel.PassiveInputStream(this, @out, 32 * 1024), false);
					daemon.SetChannel(this, GetInputStream(), @out);
					daemon.SetArg(_config.arg);
					new Sharpen.Thread(daemon).Start();
				}
				else
				{
					ChannelForwardedTCPIP.ConfigLHost _config = (ChannelForwardedTCPIP.ConfigLHost)config;
					socket = (_config.factory == null) ? Util.CreateSocket(_config.target, _config.lport, TIMEOUT) : _config.factory.CreateSocket(_config.target, _config.lport);
					socket.NoDelay = true;
					io.SetInputStream(socket.GetInputStream());
					io.SetOutputStream(socket.GetOutputStream());
				}
				SendOpenConfirmation();
			}
			catch (Exception)
			{
				SendOpenFailure(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
				close = true;
				Disconnect();
				return;
			}
			thread = Sharpen.Thread.CurrentThread();
			Buffer buf = new Buffer(rmpsize);
			Packet packet = new Packet(buf);
			int i = 0;
			try
			{
				Session _session = GetSession();
				while (thread != null && io != null && io.@in != null)
				{
					i = io.@in.Read(buf.buffer, 14, buf.buffer.Length - 14 - Session.buffer_margin);
					if (i <= 0)
					{
						Eof();
						break;
					}
					packet.Reset();
					buf.PutByte(unchecked((byte)Session.SSH_MSG_CHANNEL_DATA));
					buf.PutInt(recipient);
					buf.PutInt(i);
					buf.Skip(i);
					lock (this)
					{
						if (close)
						{
							break;
						}
						_session.Write(packet, this, i);
					}
				}
			}
			catch (Exception)
			{
			}
			//System.err.println(e);
			//thread=null;
			//eof();
			Disconnect();
		}

		internal override void GetData(Buffer buf)
		{
			SetRecipient(buf.GetInt());
			SetRemoteWindowSize(buf.GetUInt());
			SetRemotePacketSize(buf.GetInt());
			byte[] addr = buf.GetString();
			int port = buf.GetInt();
			byte[] orgaddr = buf.GetString();
			int orgport = buf.GetInt();
			Session _session = null;
			try
			{
				_session = GetSession();
			}
			catch (JSchException)
			{
			}
			// session has been already down.
			this.config = GetPort(_session, Util.Byte2str(addr), port);
			if (this.config == null)
			{
				this.config = GetPort(_session, null, port);
			}
			if (this.config == null)
			{
          if (JSch.GetLogger().IsEnabled(Logger.ERROR))
          {
              JSch.GetLogger().Log(Logger.ERROR, "ChannelForwardedTCPIP: " + Util.Byte2str(addr) + ":" + port + " is not registered.");
          }
			}
		}

		private static ChannelForwardedTCPIP.Config GetPort(Session session, string address_to_bind, int rport)
		{
			lock (pool)
			{
				for (int i = 0; i < pool.Count; i++)
				{
					ChannelForwardedTCPIP.Config bar = (ChannelForwardedTCPIP.Config)(pool[i]);
					if (bar.session != session)
					{
						continue;
					}
					if (bar.rport != rport)
					{
						if (bar.rport != 0 || bar.allocated_rport != rport)
						{
							continue;
						}
					}
					if (address_to_bind != null && !bar.address_to_bind.Equals(address_to_bind))
					{
						continue;
					}
					return bar;
				}
				return null;
			}
		}

		internal static string[] GetPortForwarding(Session session)
		{
			ArrayList foo = new ArrayList();
			lock (pool)
			{
				for (int i = 0; i < pool.Count; i++)
				{
					ChannelForwardedTCPIP.Config config = (ChannelForwardedTCPIP.Config)(pool[i]);
					if (config is ChannelForwardedTCPIP.ConfigDaemon)
					{
						foo.Add(config.allocated_rport + ":" + config.target + ":");
					}
					else
					{
						foo.Add(config.allocated_rport + ":" + config.target + ":" + ((ChannelForwardedTCPIP.ConfigLHost)config).lport);
					}
				}
			}
			string[] bar = new string[foo.Count];
			for (int i_1 = 0; i_1 < foo.Count; i_1++)
			{
				bar[i_1] = (string)(foo[i_1]);
			}
			return bar;
		}

		internal static string Normalize(string address)
		{
			if (address == null)
			{
				return "localhost";
			}
			else
			{
				if (address.Length == 0 || address.Equals("*"))
				{
					return string.Empty;
				}
				else
				{
					return address;
				}
			}
		}

		/// <exception cref="NSch.JSchException"/>
		internal static void AddPort(Session session, string _address_to_bind, int port, int allocated_port, string target, int lport, SocketFactory factory)
		{
			string address_to_bind = Normalize(_address_to_bind);
			lock (pool)
			{
				if (GetPort(session, address_to_bind, port) != null)
				{
					throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
				}
				ChannelForwardedTCPIP.ConfigLHost config = new ChannelForwardedTCPIP.ConfigLHost();
				config.session = session;
				config.rport = port;
				config.allocated_rport = allocated_port;
				config.target = target;
				config.lport = lport;
				config.address_to_bind = address_to_bind;
				config.factory = factory;
				pool.Add(config);
			}
		}

		/// <exception cref="NSch.JSchException"/>
		internal static void AddPort(Session session, string _address_to_bind, int port, int allocated_port, string daemon, object[] arg)
		{
			string address_to_bind = Normalize(_address_to_bind);
			lock (pool)
			{
				if (GetPort(session, address_to_bind, port) != null)
				{
					throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
				}
				ChannelForwardedTCPIP.ConfigDaemon config = new ChannelForwardedTCPIP.ConfigDaemon();
				config.session = session;
				config.rport = port;
				config.allocated_rport = port;
				config.target = daemon;
				config.arg = arg;
				config.address_to_bind = address_to_bind;
				pool.Add(config);
			}
		}

		internal static void DelPort(NSch.ChannelForwardedTCPIP c)
		{
			Session _session = null;
			try
			{
				_session = c.GetSession();
			}
			catch (JSchException)
			{
			}
			// session has been already down.
			if (_session != null && c.config != null)
			{
				DelPort(_session, c.config.rport);
			}
		}

		internal static void DelPort(Session session, int rport)
		{
			DelPort(session, null, rport);
		}

		internal static void DelPort(Session session, string address_to_bind, int rport)
		{
			lock (pool)
			{
				ChannelForwardedTCPIP.Config foo = GetPort(session, Normalize(address_to_bind), rport);
				if (foo == null)
				{
					foo = GetPort(session, null, rport);
				}
				if (foo == null)
				{
					return;
				}
				pool.RemoveElement(foo);
				if (address_to_bind == null)
				{
					address_to_bind = foo.address_to_bind;
				}
				if (address_to_bind == null)
				{
					address_to_bind = "0.0.0.0";
				}
			}
			Buffer buf = new Buffer(100);
			// ??
			Packet packet = new Packet(buf);
			try
			{
				// byte SSH_MSG_GLOBAL_REQUEST 80
				// string "cancel-tcpip-forward"
				// boolean want_reply
				// string  address_to_bind (e.g. "127.0.0.1")
				// uint32  port number to bind
				packet.Reset();
				buf.PutByte(unchecked((byte)80));
				buf.PutString(Util.Str2byte("cancel-tcpip-forward"));
				buf.PutByte(unchecked((byte)0));
				buf.PutString(Util.Str2byte(address_to_bind));
				buf.PutInt(rport);
				session.Write(packet);
			}
			catch (Exception)
			{
			}
		}

		//    throw new JSchException(e.toString());
		internal static void DelPort(Session session)
		{
			int[] rport = null;
			int count = 0;
			lock (pool)
			{
				rport = new int[pool.Count];
				for (int i = 0; i < pool.Count; i++)
				{
					ChannelForwardedTCPIP.Config config = (ChannelForwardedTCPIP.Config)(pool[i]);
					if (config.session == session)
					{
						rport[count++] = config.rport;
					}
				}
			}
			for (int i_1 = 0; i_1 < count; i_1++)
			{
				DelPort(session, rport[i_1]);
			}
		}

		public virtual int GetRemotePort()
		{
			return (config != null ? config.rport : 0);
		}

		private void SetSocketFactory(SocketFactory factory)
		{
			if (config != null && (config is ChannelForwardedTCPIP.ConfigLHost))
			{
				((ChannelForwardedTCPIP.ConfigLHost)config).factory = factory;
			}
		}

		internal abstract class Config
		{
			internal Session session;

			internal int rport;

			internal int allocated_rport;

			internal string address_to_bind;

			internal string target;
		}

		internal class ConfigDaemon : ChannelForwardedTCPIP.Config
		{
			internal object[] arg;
		}

		internal class ConfigLHost : ChannelForwardedTCPIP.Config
		{
			internal int lport;

			internal SocketFactory factory;
		}
	}
}
