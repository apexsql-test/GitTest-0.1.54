// -----------------------------------------------------------------------
// <copyright file="GitSessionFactoryCustomCredentials.cs" company="ApexSQL">
// Copyright (c) ApexSQL LLC. All rights reserved.
// </copyright>
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Text;
using NGit.Transport;
using NGit.Util;
using NSch;


namespace GitSSHConnectionTest
{
	/// <summary>
	/// Git Session Configuration with inserting of user credentials.
	/// </summary>
    internal class GitSessionFactoryCustomCredentials : JschConfigSessionFactory
	{
		private const string PRIVATE_KEY = @".ssh\id_rsa";
		private const string PUBLIC_KEY = @".ssh\id_rsa.pub";

		private readonly string m_login = string.Empty;
		private readonly string m_passphrase = string.Empty;

		/// <summary>
		/// Git Session Configuration with inserting of user credentials.
		/// </summary>
		/// <param name="login">The user login, for authentication on the server.</param>
		/// <param name="passphrase">The user password, for authentication on the server.</param>
		public GitSessionFactoryCustomCredentials(string login, string passphrase)
		{
			m_login = login;
			m_passphrase = passphrase;

			// Setting credentials for http connection.
			CredentialsProvider.SetDefault(new UsernamePasswordCredentialsProvider(m_login, m_passphrase));
		}

		/// <summary>
		/// Overload of session configuration. Includes user ssh keys and password in session.
		/// </summary>
		protected override void Configure(OpenSshConfig.Host hc, Session session)
		{
			// Getting user profile folder path.
			string userProfile =
				Directory.GetParent(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)).FullName;
			if(Environment.OSVersion.Version.Major >= 6)
			{
				userProfile = Directory.GetParent(userProfile).FullName;
			}

			// TODO: Add IO exception with missing ssh keys
			var privateKey = File.ReadAllText(string.Format(@"{0}\{1}", userProfile, PRIVATE_KEY));
			var publicKey = File.ReadAllText(string.Format(@"{0}\{1}", userProfile, PUBLIC_KEY));

			session.SetConfig("StrictHostKeyChecking", "no");

			// Adding user ssh credentials to session.
			var jsch = GetJSch(hc, FS.DETECTED);
			jsch.RemoveAllIdentity();
			jsch.AddIdentity(string.Format(@"{0}\{1}", userProfile, PRIVATE_KEY), Encoding.UTF8.GetBytes(privateKey),
				Encoding.UTF8.GetBytes(publicKey), Encoding.UTF8.GetBytes(m_passphrase));
		}
	}
}