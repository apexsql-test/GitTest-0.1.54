using System;
using System.IO;
using System.Reflection;
using System.Globalization;
using ApexSql.Common;
using ApexSql.Common.Logging;

public static class LogHelper
    {
        private static readonly int s_major = Assembly.GetExecutingAssembly().GetName().Version.Major;
        private static readonly string s_logFilename = string.Format(CultureInfo.InvariantCulture, "ApexSQLSourceControl{0}.log", s_major);

        /// <summary>
        /// Gets the configuration storage path for this application.
        /// </summary>
        /// <returns>Log folder path.</returns>
        public static string GetSettingsFolder()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"ApexSQL\ApexSQLSourceControl");
        }

        /// <summary>
        /// Gets the configuration storage path for previous major version of this application.
        /// </summary>
        /// <returns>Log folder path.</returns>
        public static string GetPreviousMajorSettingsFolder()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                string.Format(@"ApexSQL\ApexSQLSourceControl{0}", s_major - 1));
        }

        /// <summary>
        /// Logs exception.
        /// </summary>
        /// <param name="ex">Exception to be logged.</param>
        internal static void LogException(Exception ex)
        {
            try
            {
                InitializeLogging();
                Logger.Error("*SourceControl: Exception: {0}\r\n{1}", ex.Message, ex.StackTrace);
                if(ex.InnerException != null)
                {
                    LogException(ex.InnerException);
                }
            }
            catch
            {
                // ignore any exceptions here 
            }
        }

        /// <summary>
        /// Logs exception.
        /// </summary>
        /// <param name="message">Information to be logged.</param>
        /// <param name="ex">Exception to be logged.</param>
        public static void LogException(string message, Exception ex)
        {
            try
            {
                InitializeLogging();
                Logger.Error("*SourceControl: Exception: {0}: {1}\r\n{2}", message, ex.Message, ex.StackTrace);
                if(ex.InnerException != null)
                {
                    LogException(message, ex.InnerException);
                }
            }
            catch
            {
                // ignore any exceptions here 
            }
        }

        /// <summary>
        /// Logs information.
        /// </summary>
        /// <param name="message">Information to be logged.</param>
        public static void LogInformation(string message)
        {
            try
            {
                InitializeLogging();
                Logger.Info(String.Format("*SourceControl: {0}", message));
            }
            catch
            {
                // ignore any exceptions here 
            }
        }

        /// <summary>
        /// Logs warning.
        /// </summary>
        /// <param name="message">Warning to be logged.</param>
        public static void LogWarning(string message)
        {
            try
            {
                InitializeLogging();
                Logger.Warning(String.Format("*SourceControl: {0}", message));
            }
            catch
            {
                // ignore any exceptions here 
            }
        }

        /// <summary>
        /// Initialize log's name, path and size for logging based on Common.Logger class.
        /// </summary>
        private static void InitializeLogging()
        {
            if(!string.Equals(Logger.LogFileName, s_logFilename, StringComparison.Ordinal))
            {
                //ProductInfo.SetApplicationAssembly(Assembly.GetExecutingAssembly());
                Logger.LogFolder = GetSettingsFolder();
                Logger.LogFileName = string.Format("ApexSQLSourceControl{0}.log", s_major);
                Logger.MaxLogSize = 5242880;
                Logger.Level = LoggingLevel.All;
                //Logging.ErrorLogged += Logger.Error;
                //Logging.ExceptionLogged += Logger.Exception;
                //Logging.FatalLogged += Logger.Fatal;
                //Logging.InfoLogged += Logger.Info;
            }
        }
	}