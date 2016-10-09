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

        private const string GitHubDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\github_db01";
        private const string GitHubDir02 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\github_db02";
        private const string BitBucketDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\bitbucket_db01";
        private const string m_url_github = "git@github.com:apexsql-test/test02.git";
        private const string m_url_bitbucket = "git@bitbucket.org:apexsql_test/sql_test_04.git";
        private const string keyPairPath = "C:\\Users\\Grigoryan\\.ssh";
        private const string passPhase = "";
        private const string LogFolder = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Logs";
        private const string LogFile = "JSch.log";

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

        static void Main(string[] args)
        {
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
                ApexSql.Common.Logging.Logger.Exception(jGitInternalException);
                Console.WriteLine(jGitInternalException.Message + "\r\n" + jGitInternalException.StackTrace);
            }
            catch (Exception ex)
            {
                ApexSql.Common.Logging.Logger.Exception(ex);
                Console.WriteLine(ex.Message);
            }

            Console.WriteLine("Press any key to EXIT");
            while (!Console.KeyAvailable) ;

        }
    }
}
