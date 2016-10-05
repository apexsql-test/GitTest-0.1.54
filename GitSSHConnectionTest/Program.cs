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
        private static string m_url = string.Empty;

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

        private static void TryToClone(string localPath)
        {
            try
            {
                m_client =
                    GitClient.CloneRepository()
                        //.SetTimeout(30)
                        .SetURI(m_url)
                        .SetDirectory(localPath)
                        .SetBranchesToClone(new List<string>() { "master" })
                        .Call();

                //if (!Activebranch.Equals(NGit.Constants.MASTER))
                //{
                //    m_client.BranchCreate()
                //        .SetName(Activebranch)
                //        .SetStartPoint(OriginActivebranch)
                //        .SetUpstreamMode(CreateBranchCommand.SetupUpstreamMode.TRACK)
                //        .Call();
                //    m_client.Checkout().SetName(Activebranch).Call();
                //}

                //SetAutoclrf(false);
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
                //if (
                //    jGitInternalException.Message.Equals(
                //        string.Format(
                //            Resources.NOT_EMPTY_DIR,
                //            new DirectoryInfo(m_localPath).Name)))
                //{
                //    IOHelper.CleanDirectory(localPath, true);
                //    TryToClone(localPath);
                //    return;
                //}

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

        static void Main(string[] args)
        {
            string OutputDir01 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\sample_db01";
            string OutputDir02 = "C:\\Users\\Grigoryan\\FreeLancing\\Freelancer.com\\Git engine\\Tests\\sample_db02";
            m_url = "git@github.com:apexsql-test/test02.git";
            //m_url = "git@bitbucket.org:apexsql_test/sql_test_04.git";
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
                ClearDirectory(OutputDir01);
                DeleteEmptyRepository(OutputDir01);
                ClearDirectory(OutputDir02);
                DeleteEmptyRepository(OutputDir02);

                //m_client = Git.CloneRepository()
                //          .SetDirectory(OutputDir01)
                //          .SetURI(m_url)
                //          .SetBranchesToClone(new List<string>() { "master" })
                //          .Call();

                //m_client = GitClient.CloneRepository()
                //            //.SetTimeout(300)
                //            .SetURI(m_url)
                //            .SetDirectory(OutputDir01)
                //            .SetBranchesToClone(new List<string>() { "master" })
                //            .Call();

                //m_client = Git.CloneRepository()
                //          .SetDirectory(OutputDir02)
                //          .SetURI(m_url)
                //          .SetBranchesToClone(new List<string>() { "master" })
                //          .Call();

                //m_client = GitClient.CloneRepository()
                //            //.SetTimeout(300)
                //            .SetURI(m_url)
                //            .SetDirectory(OutputDir02)
                //            .SetBranchesToClone(new List<string>() { "master" })
                //            .Call();


                TryToClone(OutputDir01);
                TryToClone(OutputDir02);
            }
            //catch (NGit.Errors.TransportException jGitTransportException)
            //{
            //    System.Windows.Forms.MessageBox.Show(jGitTransportException.Message);
            //}
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
