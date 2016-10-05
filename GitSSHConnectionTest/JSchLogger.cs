using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using NGit.Api;
using NGit.Api.Errors;
using NGit.Diff;
using NGit.Errors;
using NGit.Revwalk;
using NGit.Transport;
using NGit.Util;

using NSch;

using ApexSql.Common.Logging;

namespace GitSSHConnectionTest
{
    class JSchLogger : NSch.Logger
    {
        public override bool IsEnabled(int level)
        {
            return true;
        }

        public override void Log(int level, string message)
        {
            switch (level)
            {
                case DEBUG:
                    ApexSql.Common.Logging.Logger.Debug(message);
                    break;
                case INFO:
                    ApexSql.Common.Logging.Logger.Info(message);
                    break;
                case WARN:
                    ApexSql.Common.Logging.Logger.Warning(message);
                    break;
                case ERROR:
                    ApexSql.Common.Logging.Logger.Error(message);
                    break;
                case FATAL:
                    ApexSql.Common.Logging.Logger.Fatal(message);
                    break;
            }
        }
    }
}
