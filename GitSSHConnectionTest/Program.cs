using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

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


namespace GitSSHConnectionTest
{
    class Program
    {
        private static GitClient m_client;

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
                DeleteEmptyRepository(localPath);
                //throw new AuthenticationException(Resources.COULD_NOT_CONNECT);
                throw nullReferenceException;
            }
            catch (JGitInternalException jGitInternalException)
            {
                ApexSql.Common.Logging.Logger.Exception(jGitInternalException);
                DeleteEmptyRepository(localPath);
                //throw new AuthenticationException(Resources.AUTH_ACCESS_DENIED);
                throw jGitInternalException;
            }
            catch (Exception e)
            {
                ApexSql.Common.Logging.Logger.Exception(e);
                DeleteEmptyRepository(localPath);
                //throw new AuthenticationException(Resources.COULD_NOT_CONNECT_MESSAGE, e.Message);
                throw e;
            }
        }

        static void runTest(string dir, string url)
        {
            ClearDirectory(dir);
            DeleteEmptyRepository(dir);
            TryToClone(dir, url);
        }

        static void Main(string[] args)
        {
            string GitHubDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\github_db01";
            string GitHubDir02 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\github_db02";
            string BitBucketDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\bitbucket_db01";
            string m_url_github = "git@github.com:apexsql-test/test02.git";
            string m_url_bitbucket = "git@bitbucket.org:apexsql_test/sql_test_04.git";
            string keyPairPath = "C:\\Users\\Grigoryan\\.ssh";
            string passPhase = "";
            string LogFolder = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Logs";
            string LogFile = "JSch.log";

            ApexSql.Common.Logging.Logger.LogFolder = LogFolder;
            ApexSql.Common.Logging.Logger.LogFileName = LogFile;
            ApexSql.Common.Logging.Logger.MaxLogSize = 5242880;
            ApexSql.Common.Logging.Logger.Level = ApexSql.Common.Logging.LoggingLevel.All;

            JSch.SetLogger(new JSchLogger());

            var sshSessionFactory = new GitSessionFactorySSHCredentials();
            sshSessionFactory.Passphase = passPhase;
            sshSessionFactory.KeyPairPath = keyPairPath;

            NGit.Transport.JschConfigSessionFactory.SetInstance(sshSessionFactory);

            try
            {
                runTest(GitHubDir01, m_url_github);
                runTest(GitHubDir02, m_url_github);
                runTest(BitBucketDir01, m_url_bitbucket);
            }
            catch (JGitInternalException jGitInternalException)
            {
                //Logger.Exception(jGitInternalException);
                Trace.Write(jGitInternalException.Message + "\r\n" + jGitInternalException.StackTrace);
            }
            catch (Exception ex)
            {
                //Logger.Exception(ex);
                Trace.Write(ex.Message);
            }

        }
    }
}
