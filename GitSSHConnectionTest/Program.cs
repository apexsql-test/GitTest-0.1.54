using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;

using NSch;
using NGit.Api;
using NGit.Api.Errors;
using NGit.Diff;
using NGit.Errors;
using NGit.Revwalk;
using NGit.Transport;
using NGit.Util;

using Constants = NGit.Constants;
using GitClient = NGit.Api.Git;

using Microsoft.Alm.Authentication;

namespace GitSSHConnectionTest
{
    class Program
    {
        private static GitClient m_client;
        private static Credential m_vsoCredentials;
        private const string keyPairPath = "C:\\Users\\Grigoryan\\.ssh";
        private const string GitHubDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\github_db01";
        private const string BitBucketDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\bitbucket_db01";
        private const string VsoDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\vso_db1";
        private const string TfsDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\\\Tests\\tfs_db1";
        private const string TfsSSHDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\_git_tfs_ssh";

        const int TIMEOUT_IN_MILLISECONDS = 120000;

        private static void ClearDirectory(string targetDirectory)
        {
            foreach (string directory in Directory.GetDirectories(targetDirectory))
            {
                foreach (string file in Directory.GetFiles(directory))
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                    File.Delete(file);
                }
                ClearDirectory(directory);
                Directory.Delete(directory);
            }
        }

        private static void DeleteEmptyRepository(string repositoryPath)
        {
            var isEmptyRepo = m_client == null || m_client.GetRepository().Resolve(NGit.Constants.HEAD) == null;
            if (isEmptyRepo)
            {
                //Logout();
                ClearDirectory(repositoryPath);
                if (Directory.Exists(string.Format("{0}\\.git", repositoryPath)))
                {
                    Directory.Delete(string.Format("{0}\\.git", repositoryPath), true);
                }
            }
        }

        private static void TryToClone(string localPath, string url)
        {
            Console.WriteLine("Cloning:" + url);
            Console.WriteLine("To:" + localPath);

            try
            {
                m_client =
                    GitClient.CloneRepository()
                        //.SetTimeout(30)
                        .SetURI(url)
                        .SetDirectory(localPath)
                        .SetBranchesToClone(new List<string>() { "master" })
                        .Call();
            }
            catch (NullReferenceException nullReferenceException)
            {
                ApexSql.Common.Logging.Logger.Exception(nullReferenceException);
                Console.WriteLine(nullReferenceException.Message);
                ClearDirectory(localPath);
                DeleteEmptyRepository(localPath);
                throw nullReferenceException;
            }
            catch (JGitInternalException jGitInternalException)
            {
                ApexSql.Common.Logging.Logger.Exception(jGitInternalException);
                Console.WriteLine(jGitInternalException.Message);
                ClearDirectory(localPath);
                DeleteEmptyRepository(localPath);
                throw jGitInternalException;
            }
            catch (Exception e)
            {
                ApexSql.Common.Logging.Logger.Exception(e);
                Console.WriteLine(e.Message);
                ClearDirectory(localPath);
                DeleteEmptyRepository(localPath);
                throw e;
            }

            Console.WriteLine("Ok");

        }

        static void runTest(string dir, string url)
        {
            ClearDirectory(dir);
            DeleteEmptyRepository(dir);
            TryToClone(dir, url);
        }

        static void runSSHTest()
        {
            const string github_url = "git@github.com:apexsql-test/test02.git";
            const string bitbucket_url = "git@bitbucket.org:apexsql_test/sql_test_04.git";
            const string passPhase = "";

            var sshSessionFactory = new GitSessionFactorySSHCredentials();
            sshSessionFactory.Passphase = passPhase;
            sshSessionFactory.KeyPairPath = keyPairPath;

            NGit.Transport.JschConfigSessionFactory.SetInstance(sshSessionFactory);

            try
            {
                runTest(GitHubDir01, github_url);
                //runTest(GitHubDir02, github_url);
                runTest(BitBucketDir01, bitbucket_url);
            }
            catch (JGitInternalException jGitInternalException)
            {
                ApexSql.Common.Logging.Logger.Exception(jGitInternalException);
                Console.WriteLine(jGitInternalException.Message + "\r\n" + jGitInternalException.StackTrace);
            }
            catch (Exception ex)
            {
                ApexSql.Common.Logging.Logger.Exception(ex);
                Console.WriteLine(ex.Message);
            }
        }

        static void runHTTPSTest()
        {
            const string github_login = "apexsql-test";
            const string github_pswd = "apex_SQL01";
            const string github_url = "https://github.com/apexsql-test/test02.git";

            const string bitbucket_login = "apexsql_test";
            const string bitbucket_pswd = "apex_SQL";
            const string bitbucket_url = "https://apexsql_test@bitbucket.org/apexsql_test/sql_test_04.git";

            try
            {
                SshSessionFactory.SetInstance(new GitSessionFactoryCustomCredentials(github_login, github_pswd));
                runTest(GitHubDir01, github_url);
                //runTest(GitHubDir02, github_url);

                SshSessionFactory.SetInstance(new GitSessionFactoryCustomCredentials(bitbucket_login, bitbucket_pswd));
                runTest(BitBucketDir01, bitbucket_url);
            }
            catch (JGitInternalException jGitInternalException)
            {
                ApexSql.Common.Logging.Logger.Exception(jGitInternalException);
                Console.WriteLine(jGitInternalException.Message + "\r\n" + jGitInternalException.StackTrace);
            }
            catch (Exception ex)
            {
                ApexSql.Common.Logging.Logger.Exception(ex);
                Console.WriteLine(ex.Message);
            }
        }

        static void GetVSOCredential(TargetUri target, SecretStore secrets, VstsTokenScope VstsCredentialScope)
        {
            Credential credentialToTry = null;
            VstsMsaAuthentication msaAuth = new VstsMsaAuthentication(VstsCredentialScope, secrets);

            // Try getting the credentails from the store.
            // If does not work try getting credentials with interactive login.
            // Credentials must be verified in both cases
            Task.Run(async () =>
            {
                if (((credentialToTry = msaAuth.GetCredentials(target)) != null) &&
                    (await msaAuth.ValidateCredentials(target, credentialToTry)) 
                    || ((credentialToTry = await msaAuth.InteractiveLogon(target, true)) != null) &&
                    (await msaAuth.ValidateCredentials(target, credentialToTry)))
                {
                    m_vsoCredentials = credentialToTry;
                }
            }).Wait(TIMEOUT_IN_MILLISECONDS);
        }

        static void GetTFSCredential(TargetUri target, SecretStore secrets, VstsTokenScope VstsCredentialScope)
        {
            Credential credentialToTry = null;
            Guid tenantId = Guid.Empty;
            // return the allocated authority or a generic AAD backed VSTS authentication object
            VstsAadAuthentication aadAuth = new VstsAadAuthentication(Guid.Empty, VstsCredentialScope, secrets);

            // Try getting the credentails from the store.
            // If does not work try getting credentials with interactive login.
            // Credentials must be verified in both cases
            Task.Run(async () =>
            {
                if (((credentialToTry = aadAuth.GetCredentials(target)) != null) &&
                    (await aadAuth.ValidateCredentials(target, credentialToTry))
                    || ((credentialToTry = await aadAuth.InteractiveLogon(target, true)) != null) &&
                    (await aadAuth.ValidateCredentials(target, credentialToTry)))
                {
                    m_vsoCredentials = credentialToTry;
                }
            }).Wait(TIMEOUT_IN_MILLISECONDS);
        }

        static void run_VSO_HTTPS_Test()
        {
            string vso_url = "https://harut70.visualstudio.com/_git/ApexSQL%20VSO%20version";
            //TargetUri target = new TargetUri("https://harut70.visualstudio.com/_git");
            TargetUri target = new TargetUri("https://harut70.visualstudio.com/");
            //string username = "harut70";

            m_vsoCredentials = null;

            try
            {
                const string GIT_NAMESPACE = "git";
                VstsTokenScope VstsCredentialScope = VstsTokenScope.CodeWrite | VstsTokenScope.PackagingRead;
                var secrets = new SecretStore(GIT_NAMESPACE, null, null, Secret.UriToName);

                BaseAuthentication authority = 
                    BaseVstsAuthentication.GetAuthentication(target,
                                                            VstsCredentialScope,
                                                            secrets);
                if (null == authority)
                {
                    throw new NullReferenceException();
                }

                if (authority is VstsMsaAuthentication)
                {
                    GetVSOCredential(target, secrets, VstsCredentialScope);
                }
                else if (authority is VstsAadAuthentication)
                {
                    GetTFSCredential(target, secrets, VstsCredentialScope);
                }

                if (null == m_vsoCredentials)
                {
                    throw new NullReferenceException();
                }

                SshSessionFactory.SetInstance(new GitSessionFactoryCustomCredentials(m_vsoCredentials.Username, m_vsoCredentials.Password));
                //SshSessionFactory.SetInstance(new GitSessionFactoryCustomCredentials(username, pswd));
                runTest(VsoDir01, vso_url);
            }
            catch (JGitInternalException jGitInternalException)
            {
                ApexSql.Common.Logging.Logger.Exception(jGitInternalException);
                Console.WriteLine(jGitInternalException.Message + "\r\n" + jGitInternalException.StackTrace);
            }
            catch (Exception ex)
            {
                ApexSql.Common.Logging.Logger.Exception(ex);
                Console.WriteLine(ex.Message);
            }

        }

        static void run_TFS_HTTPS_Test()
        {

            string tfs_url = "https://grigoryanharutiun.visualstudio.com/DefaultCollection/_git/HarutTest";
            TargetUri target = new TargetUri("https://grigoryanharutiun.visualstudio.com/");
            //string username = "grigoryanharutiun@milosdjosovicapexsql.onmicrosoft.com";

            m_vsoCredentials = null;

            try
            {
                const string GIT_NAMESPACE = "git";
                VstsTokenScope VstsCredentialScope = VstsTokenScope.CodeWrite | VstsTokenScope.PackagingRead;
                var secrets = new SecretStore(GIT_NAMESPACE, null, null, Secret.UriToName);

                BaseAuthentication authority =
                    BaseVstsAuthentication.GetAuthentication(target,
                                                            VstsCredentialScope,
                                                            secrets);
                if (null == authority)
                {
                    throw new NullReferenceException();
                }

                if (authority is VstsMsaAuthentication)
                {
                    GetVSOCredential(target, secrets, VstsCredentialScope);
                }
                else if (authority is VstsAadAuthentication)
                {
                    GetTFSCredential(target, secrets, VstsCredentialScope);
                }

                if (null == m_vsoCredentials)
                {
                    throw new NullReferenceException();
                }

                SshSessionFactory.SetInstance(new GitSessionFactoryCustomCredentials(m_vsoCredentials.Username, m_vsoCredentials.Password));
                //SshSessionFactory.SetInstance(new GitSessionFactoryCustomCredentials(username, pswd));

                runTest(TfsDir01, tfs_url);
  
            }
            catch (JGitInternalException jGitInternalException)
            {
                ApexSql.Common.Logging.Logger.Exception(jGitInternalException);
                Console.WriteLine(jGitInternalException.Message + "\r\n" + jGitInternalException.StackTrace);
            }
            catch (Exception ex)
            {
                ApexSql.Common.Logging.Logger.Exception(ex);
                Console.WriteLine(ex.Message);
            }

        }

        static void run_VSO_SSH_Test()
        {
            const string vso_url = "ssh://harut70@harut70.visualstudio.com:22/_git/ApexSQL%20VSO%20version";
            const string passPhase = "";

            var sshSessionFactory = new GitSessionFactorySSHCredentials();
            sshSessionFactory.Passphase = passPhase;
            sshSessionFactory.KeyPairPath = keyPairPath;

            NGit.Transport.JschConfigSessionFactory.SetInstance(sshSessionFactory);

            try
            {
                runTest(VsoDir01, vso_url);
            }
            catch (JGitInternalException jGitInternalException)
            {
                ApexSql.Common.Logging.Logger.Exception(jGitInternalException);
                Console.WriteLine(jGitInternalException.Message + "\r\n" + jGitInternalException.StackTrace);
            }
            catch (Exception ex)
            {
                ApexSql.Common.Logging.Logger.Exception(ex);
                Console.WriteLine(ex.Message);
            }
        }

        static void run_TFS_SSH_Test()
        {
            const string vso_url = "ssh://grigoryanharutiun@grigoryanharutiun.visualstudio.com:22/_git/HarutTest";
            const string passPhase = "";

            var sshSessionFactory = new GitSessionFactorySSHCredentials();
            sshSessionFactory.Passphase = passPhase;
            sshSessionFactory.KeyPairPath = keyPairPath;

            NGit.Transport.JschConfigSessionFactory.SetInstance(sshSessionFactory);

            try
            {
                runTest(TfsSSHDir01, vso_url);
            }
            catch (JGitInternalException jGitInternalException)
            {
                ApexSql.Common.Logging.Logger.Exception(jGitInternalException);
                Console.WriteLine(jGitInternalException.Message + "\r\n" + jGitInternalException.StackTrace);
            }
            catch (Exception ex)
            {
                ApexSql.Common.Logging.Logger.Exception(ex);
                Console.WriteLine(ex.Message);
            }
        }

        static void Main(string[] args)
        {
            const string LogFolder = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Logs";
            const string LogFile = "JSch.log";

            ApexSql.Common.Logging.Logger.LogFolder = LogFolder;
            ApexSql.Common.Logging.Logger.LogFileName = LogFile;
            ApexSql.Common.Logging.Logger.MaxLogSize = 5242880;
            ApexSql.Common.Logging.Logger.Level = ApexSql.Common.Logging.LoggingLevel.All;

            JSch.SetLogger(new JSchLogger());

            //runSSHTest();
            //run_VSO_SSH_Test();
            run_TFS_SSH_Test();

            //runHTTPSTest();
            //run_VSO_HTTPS_Test();
            //run_TFS_HTTPS_Test();

            Console.WriteLine("Press any key to EXIT");
            while (!Console.KeyAvailable) ;

        }
    }
}
