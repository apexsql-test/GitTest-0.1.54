﻿// -----------------------------------------------------------------------
// <copyright file="GitSessionFactorySSHCredentials.cs" company="ApexSQL">
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
    public class KeyPairNotFoundException : Exception
    {
    }

    /// <summary>
    /// Git Session Configuration with SSH credentials.
    /// </summary>
    internal class GitSessionFactorySSHCredentials : JschConfigSessionFactory
    {
        private const string PRIVATE_KEY = @"\id_rsa";
        private const string PUBLIC_KEY = @"\id_rsa.pub";

        public string Passphase { get; set; }

        public string KeyPairPath { get; set; }

        /// <summary>
        /// Overload of session configuration. Includes user ssh keys and password in session.
        /// </summary>
        protected override void Configure(OpenSshConfig.Host hc, Session session)
        {
            // TODO: Add IO exception with missing ssh keys
            var privateKeyPath = string.Format(@"{0}\{1}", KeyPairPath, PRIVATE_KEY);
            var publicKeyPath = string.Format(@"{0}\{1}", KeyPairPath, PUBLIC_KEY);

            if (!File.Exists(privateKeyPath) || !File.Exists(publicKeyPath))
            {
                throw new KeyPairNotFoundException();
            }

            var privateKey = File.ReadAllText(privateKeyPath);
            var publicKey = File.ReadAllText(publicKeyPath);

            var config = new Sharpen.Properties();
            config["StrictHostKeyChecking"] = "no";
            config["PreferredAuthentications"] = "publickey";
            session.SetConfig(config);

            var jschConfig = new Sharpen.Properties();
            jschConfig["cipher.s2c"] = "aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,arcfour256,arcfour128";
            jschConfig["cipher.c2s"] = "aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc,arcfour256,arcfour128";
            JSch.SetConfig(jschConfig);

            // Adding user ssh credentials to session.
            var jsch = GetJSch(hc, FS.DETECTED);
            jsch.RemoveAllIdentity();
            jsch.AddIdentity("KeyPair", 
                Encoding.UTF8.GetBytes(privateKey), 
                Encoding.UTF8.GetBytes(publicKey), 
                string.IsNullOrEmpty(Passphase) ? null : Encoding.UTF8.GetBytes(Passphase));
        }
    }
}
