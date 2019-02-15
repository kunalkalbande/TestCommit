using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace sqlconnectionTest
{
    class Program
    {
        static string connstring = "Data Source=ultp_597;uid=synerzipune\\kunalk;pwd=Pulsar6419@;Integrated Security=SSPI;Initial Catalog=Prompt_NOCCCD;";
    
        static void Main(string[] args)
        {
            SqlConnection conn = new SqlConnection(connstring);
            //conn.Open();
            bool isupdate = false;
            try
            {

                string instance = ",1433";
                var nameinst = "sql2016,1433";
                var inst = instance.Trim(',');
                var inst1 = nameinst.Trim(',');
                var Username = "kunalk";
                var Domain = "synerzipune";
                var Password = "Pulsar6419@";
                using (new Impersonator(Username, Domain, Password))
                {
                    using (SqlConnection connection = new SqlConnection(connstring))
                    {

                     

                       

                        connection.Open();

                        using (SqlCommand selectcmd = new SqlCommand(String.Format("select *  from SOV"), connection))
                        {
                            using (SqlDataReader selectreader = selectcmd.ExecuteReader())
                            {
                                DataTable dt = new DataTable();
                                dt.Load(selectreader);
                                if (selectreader != null)
                                {
                                    //while (selectreader.Read())
                                    //{
                                    //    isupdate = true;
                                    //}
                                }
                            } // reader closed and disposed up here

                        } // command disposed here

                    }
                    string sql;
                    string _timeCreated = DateTime.Now.ToString();
                    SqlCommand cmd;
                    if (isupdate)
                    {
                        sql = String.Format("update Docusign_Elements set SignerName='{1}',SignerEmail='{2}',Status='{3}',TimeSent='{4}'"
                            + ",TimeDelivered='{5}',TimeSigned='{6}',TimeDelclined='{7}',DeclinedReason='{8}',PdfBytes='{9}',xml='{10}',CollegeID='{11}',ProjectID='{12}',ContractID='{13}',TimeCreated='{14}'"
                            + " where EnvelopId='{0}' and SignerName = '{1}'"
                            , "1", "tanvi", "tanvi@syn.com", "", "", "", "", "", "", "", "", "", "", "", _timeCreated);

                    }
                    else
                    {
                        sql = String.Format("insert into Docusign_Elements (EnvelopId,SignerName,SignerEmail,Status,TimeSent,TimeDelivered,TimeSigned,TimeDelclined,DeclinedReason,PdfBytes,xml,CollegeID,ProjectID,ContractID,TimeCreated)" +
                            "values ('{0}','{1}','{2}','{3}','{4}','{5}','{6}','{7}','{8}','{9}','{10}','{11}','{12}','{13}','{14}')"
                            , "1", "tanvi", "tanvi@syn.com", "", "", "", "", "", "", "", "", "", "", "", _timeCreated);
                    }
                    cmd = new SqlCommand(sql);

                    cmd.Connection = conn;
                    var result = cmd.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                var r = ex.Message;
            }
            finally
            {
                conn.Close();
            }
        }
    }
    public class Impersonator :
       IDisposable
    {
        #region Public methods.
        // ------------------------------------------------------------------

        /// <summary>
        /// Constructor. Starts the impersonation with the given credentials.
        /// Please note that the account that instantiates the Impersonator class
        /// needs to have the 'Act as part of operating system' privilege set.
        /// </summary>
        /// <param name="userName">The name of the user to act as.</param>
        /// <param name="domainName">The domain name of the user to act as.</param>
        /// <param name="password">The password of the user to act as.</param>
        public Impersonator(
            string userName,
            string domainName,
            string password)
        {
            ImpersonateValidUser(userName, domainName, password);
        }

        // ------------------------------------------------------------------
        #endregion

        #region IDisposable member.
        // ------------------------------------------------------------------

        public void Dispose()
        {
            UndoImpersonation();
        }

        // ------------------------------------------------------------------
        #endregion

        #region P/Invoke.
        // ------------------------------------------------------------------

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int LogonUser(
            string lpszUserName,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int DuplicateToken(
            IntPtr hToken,
            int impersonationLevel,
            ref IntPtr hNewToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool RevertToSelf();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern bool CloseHandle(
            IntPtr handle);

        private const int LOGON32_LOGON_INTERACTIVE = 2;
        private const int LOGON32_PROVIDER_DEFAULT = 0;

        // ------------------------------------------------------------------
        #endregion

        #region Private member.
        // ------------------------------------------------------------------

        /// <summary>
        /// Does the actual impersonation.
        /// </summary>
        /// <param name="userName">The name of the user to act as.</param>
        /// <param name="domainName">The domain name of the user to act as.</param>
        /// <param name="password">The password of the user to act as.</param>
        private void ImpersonateValidUser(
            string userName,
            string domain,
            string password)
        {
            WindowsIdentity tempWindowsIdentity = null;
            IntPtr token = IntPtr.Zero;
            IntPtr tokenDuplicate = IntPtr.Zero;

            try
            {
                if (RevertToSelf())
                {
                    if (LogonUser(
                        userName,
                        domain,
                        password,
                        LOGON32_LOGON_INTERACTIVE,
                        LOGON32_PROVIDER_DEFAULT,
                        ref token) != 0)
                    {
                        if (DuplicateToken(token, 2, ref tokenDuplicate) != 0)
                        {
                            tempWindowsIdentity = new WindowsIdentity(tokenDuplicate);
                            impersonationContext = tempWindowsIdentity.Impersonate();
                        }
                        else
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                    }
                    else
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                }
                else
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                if (token != IntPtr.Zero)
                {
                    CloseHandle(token);
                }
                if (tokenDuplicate != IntPtr.Zero)
                {
                    CloseHandle(tokenDuplicate);
                }
            }
        }

        /// <summary>
        /// Reverts the impersonation.
        /// </summary>
        private void UndoImpersonation()
        {
            if (impersonationContext != null)
            {
                impersonationContext.Undo();
            }
        }

        private WindowsImpersonationContext impersonationContext = null;

        // ------------------------------------------------------------------
        #endregion
    }

    /////////////////////////////////////////////////////////////////////////
}
