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
using Sharpen;

namespace NSch
{
	public interface ConfigRepository
	{
		ConfigRepository.Config getConfig(string host);

		public interface Config
		{
			string getHostname();

			string getUser();

			int getPort();

			string getValue(string key);

			string[] getValues(string key);
		}

		private sealed class _Config_44 : ConfigRepository.Config
		{
			public _Config_44()
			{
			}

			public string getHostname()
			{
				return null;
			}

			public string getUser()
			{
				return null;
			}

			public int getPort()
			{
				return -1;
			}

			public string getValue(string key)
			{
				return null;
			}

			public string[] getValues(string key)
			{
				return null;
			}
		}

		private sealed class _ConfigRepository_52 : ConfigRepository
		{
			public _ConfigRepository_52()
			{
			}

			public ConfigRepository.Config getConfig(string host)
			{
				return ConfigRepository.defaultConfig;
			}
		}
	}

	public static class ConfigRepositoryConstants
	{
		public const ConfigRepository.Config defaultConfig = new _Config_44();

		public const ConfigRepository nullConfig = new _ConfigRepository_52();
	}
}
