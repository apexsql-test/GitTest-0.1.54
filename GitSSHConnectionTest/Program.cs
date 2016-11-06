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

            Console.WriteLine("Repo Cloned");

        }

        static void runTest(string localPath, string url)
        {
            ClearDirectory(localPath);
            DeleteEmptyRepository(localPath);
            TryToClone(localPath, url);

            try
            {
                string LoginName = "";
                //if (m_client.GetRepository().Resolve(NGit.Constants.HEAD) == null)
                {
                    m_client.Commit()
                        .SetAuthor(LoginName, string.Empty)
                        .SetCommitter(LoginName, string.Empty)
                        .SetMessage("Initialization")
                        .Call();
                    m_client.Push().Call();

                    Console.WriteLine("Repo Initialized");
                }
            }
            catch (Exception e)
            {
                ClearDirectory(localPath);
                DeleteEmptyRepository(localPath);
                throw e;
            }

        }

        static void runSSHTest(string url, string repo)
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string keyPairPath = userProfile + "\\.ssh";
            string passPhase = "";

            var sshSessionFactory = new GitSessionFactorySSHCredentials();
            sshSessionFactory.Passphase = passPhase;
            sshSessionFactory.KeyPairPath = keyPairPath;

            Directory.CreateDirectory(repo);

            NGit.Transport.JschConfigSessionFactory.SetInstance(sshSessionFactory);

            try
            {
                runTest(repo, url);
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

        static void run_GitHub_SSH_Test(string repo)
        {
            //const string github_url = "git@github.com:apexsql-test/test02.git";
            const string github_url = "git@github.com:apexsql-test/gitrepo.git";
            runSSHTest(github_url, repo);
        }

        static void run_Bitbucket_SSH_Test(string repo)
        {
            const string bitbucket_url = "git@bitbucket.org:apexsql_test/sql_test_04.git";
            runSSHTest(bitbucket_url, repo);
        }

        static void run_VSO_SSH_Test(string repo)
        {
            const string vso_url = "ssh://harut70@harut70.visualstudio.com:22/ApexSQL%20VSO%20version/_git/TestRepo01";
            runSSHTest(vso_url, repo);
        }

        static void run_TFS_SSH_Test(string repo)
        {
            const string tfs_url = "ssh://grigoryanharutiun@grigoryanharutiun.visualstudio.com:22/_git/HarutTest";
            runSSHTest(tfs_url, repo);
        }

        static void run_BitBucketAD_SSH_Test(string repo)
        {
            //const string url = "ssh://git@lima.eastus.cloudapp.azure.com:7999/tes/testrepository.git";
            const string url = "ssh://git@lima.eastus.cloudapp.azure.com:7999/sctes/sc_test_repo.git";
            runSSHTest(url, repo);
        }

        static void runHTTPSTest(string repo, string url, string login, string pswd)
        {
            Directory.CreateDirectory(repo);

            try
            {
                SshSessionFactory.SetInstance(new GitSessionFactoryCustomCredentials(login, pswd));
                runTest(repo, url);
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

        static void run_Github_HTTPS_Test(string repo)
        {
            const string github_login = "apexsql-test";
            const string github_pswd = "apex_SQL01";
            //const string github_url = "https://github.com/apexsql-test/test02.git";
            const string github_url = "https://github.com/apexsql-test/gitrepo.git";

            runHTTPSTest(repo, github_url, github_login, github_pswd);
        }

        static void run_Bitbucket_HTTPS_Test(string repo)
        {
            const string bitbucket_login = "apexsql_test";
            const string bitbucket_pswd = "apex_SQL";
            const string bitbucket_url = "https://apexsql_test@bitbucket.org/apexsql_test/sql_test_04.git";

            runHTTPSTest(repo, bitbucket_url, bitbucket_login, bitbucket_pswd);
        }

        static void run_BitBucketAD_HTTP_Test(string repo)
        {
            const string bitbucket_login = "Harut";
            const string bitbucket_pswd = "49GEHNYVWcxmz";
            const string bitbucket_url = "http://lima.eastus.cloudapp.azure.com:7990/git/tes/TestRepository.git";

            runHTTPSTest(repo, bitbucket_url, bitbucket_login, bitbucket_pswd);
        }

        static void run_VSO_HTTPS_Test(string repo)
        {
            string vso_url = "https://harut70.visualstudio.com/ApexSQL%20VSO%20version/_git/TestRepo02";
            TargetUri target = new TargetUri("https://harut70.visualstudio.com/_git");
            string username = "harut70";

            m_vsoCredentials = null;

            try
            {
                const string GIT_NAMESPACE = "git";
                VstsTokenScope VstsCredentialScope = VstsTokenScope.CodeWrite | VstsTokenScope.PackagingRead;
                var secrets = new SecretStore(GIT_NAMESPACE, null, null, Secret.UriToName);

                BaseAuthentication authority = BaseVstsAuthentication.GetAuthentication(target, VstsCredentialScope, secrets);

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

                runHTTPSTest(repo, vso_url, username, m_vsoCredentials.Password);

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

        static void run_TFS_HTTPS_Test(string repo)
        {

            TargetUri target = new TargetUri("https://grigoryanharutiun.visualstudio.com/");
            string tfs_url = "https://grigoryanharutiun.visualstudio.com/DefaultCollection/_git/HarutTest";
            string username = "grigoryanharutiun@milosdjosovicapexsql.onmicrosoft.com";

            m_vsoCredentials = null;

            try
            {
                const string GIT_NAMESPACE = "git";
                VstsTokenScope VstsCredentialScope = VstsTokenScope.CodeWrite | VstsTokenScope.PackagingRead;
                var secrets = new SecretStore(GIT_NAMESPACE, null, null, Secret.UriToName);

                BaseAuthentication authority =  BaseVstsAuthentication.GetAuthentication(target, VstsCredentialScope, secrets);

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

                runHTTPSTest(repo, tfs_url, username, m_vsoCredentials.Password);

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

        static void Main(string[] args)
        {
            string userAppData = Directory.GetParent(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)).FullName;

            string TestFolder = userAppData + "\\Test";
            string LogFolder = userAppData + "\\Log";
            string LogFile = "JSch.log";

            string GithubHTTPSDir = TestFolder + "\\github_https";
            string GithubSSHSDir = TestFolder + "\\github_ssh";

            string BitbucketHTTPSDir = TestFolder + "\\bitbucket_https";
            string BitbucketSSHSDir = TestFolder + "\\bitbucket_ssh";

            string VsoHTTPSDir = TestFolder + "\\vso_https";
            string VSOSSHDir = TestFolder + "\\vso_ssh";

            string TfsHTTPSDir = TestFolder + "\\tfs_https";
            string TfsSSHDir = TestFolder + "\\tfs_ssh";

            string BitBucketAD_SSHDir = TestFolder + "\\bitbucket_ad_ssh";
            string BitBucketAD_HTTPDir = TestFolder + "\\bitbucket_ad_http";

            Directory.CreateDirectory(TestFolder);
            Directory.CreateDirectory(LogFolder);

            ApexSql.Common.Logging.Logger.LogFolder = LogFolder;
            ApexSql.Common.Logging.Logger.LogFileName = LogFile;
            ApexSql.Common.Logging.Logger.MaxLogSize = 5242880;
            ApexSql.Common.Logging.Logger.Level = ApexSql.Common.Logging.LoggingLevel.All;

            JSch.SetLogger(new JSchLogger());

            // HTTPS test section
            //run_Github_HTTPS_Test(GithubHTTPSDir);
            //run_Bitbucket_HTTPS_Test(BitbucketHTTPSDir);
            //run_TFS_HTTPS_Test(TfsHTTPSDir);
            //run_BitBucketAD_HTTP_Test(BitBucketAD_HTTPDir);

            // SSH test section
            //run_GitHub_SSH_Test(GithubSSHSDir);
            //run_Bitbucket_SSH_Test(BitbucketSSHSDir);
            //run_TFS_SSH_Test(TfsSSHDir);
            //run_BitBucketAD_SSH_Test(BitBucketAD_SSHDir);

            //run_VSO_HTTPS_Test(VsoHTTPSDir);
            run_VSO_SSH_Test(VSOSSHDir);

            Console.WriteLine("Press any key to EXIT");
            while (!Console.KeyAvailable) ;

        }
    }
}
