using System;
using System.Security.Principal;

using Vanara.InteropServices;
using Vanara.PInvoke;
using static Vanara.PInvoke.Authz;
using static Vanara.PInvoke.AdvApi32;

internal class Authz
{
    static void Main(string [] args)
    {
        string sidString;
        if (args.Length < 1)
        {
            // Получаем SID текущего пользователя
            var currentUser = WindowsIdentity.GetCurrent();
            var currentSid = currentUser.User;
            // Получаем SID домена
            var domainSid = currentSid.AccountDomainSid;
            // Формируем SID администратора домена (RID 500)
            sidString = domainSid.Value + "-500";
            Console.WriteLine($"Аргумент не задан. Используется SID администратора домена: {sidString}");
        }
        else
        {
            sidString = args [0];
        }

        // Получаем имя домена
        string domainName;
        try
        {
            domainName = System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain().Name;
        }
        catch
        {
            domainName = Environment.UserDomainName;
        }

        Console.WriteLine($"Используется домен: {domainName}");

        var success = Vanara.PInvoke.Authz.AuthzInitializeResourceManager(
            Vanara.PInvoke.Authz.AuthzResourceManagerFlags.AUTHZ_RM_FLAG_NO_AUDIT,
            null, null, null, domainName, out var rm);

        if (!success)
        {
            ReportLastError("AuthzInitializeResourceManager");
            return;
        }

        var sid = new SecurityIdentifier(sidString);
        var psid = new SafePSID(sid);

        success = Vanara.PInvoke.Authz.AuthzInitializeContextFromSid(
            Vanara.PInvoke.Authz.AuthzContextFlags.DEFAULT,
            psid, rm, IntPtr.Zero, new LUID(), IntPtr.Zero, out var context);

        var lasterror = Win32Error.GetLastError();
        if (!lasterror.Succeeded)
        {
            ReportLastError("AuthzInitializeContextFromSid");
            Vanara.PInvoke.Authz.AuthzFreeResourceManager(rm);
            return;
        }

        success = Vanara.PInvoke.Authz.AuthzGetInformationFromContext(
            context,
            Vanara.PInvoke.Authz.AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoGroupsSids,
            0, out var sizeRequired, IntPtr.Zero);

        lasterror = Win32Error.GetLastError();
        if (!(lasterror.Succeeded || lasterror == Win32Error.ERROR_INSUFFICIENT_BUFFER))
        {
            ReportLastError("AuthzGetInformationFromContext part 1");
            Vanara.PInvoke.Authz.AuthzFreeContext(context);
            Vanara.PInvoke.Authz.AuthzFreeResourceManager(rm);
            return;
        }

        if (sizeRequired == 0)
        {
            Console.WriteLine("Нет доступной информации о контексте.");
            Vanara.PInvoke.Authz.AuthzFreeContext(context);
            Vanara.PInvoke.Authz.AuthzFreeResourceManager(rm);
            return;
        }

        uint size = sizeRequired;
        var buffer = new SafeHGlobalHandle(size);

        success = Vanara.PInvoke.Authz.AuthzGetInformationFromContext(
            context,
            Vanara.PInvoke.Authz.AUTHZ_CONTEXT_INFORMATION_CLASS.AuthzContextInfoGroupsSids,
            size, out sizeRequired, buffer);

        if (!success)
        {
            ReportLastError("AuthzGetInformationFromContext part 2");
            Vanara.PInvoke.Authz.AuthzFreeContext(context);
            Vanara.PInvoke.Authz.AuthzFreeResourceManager(rm);
            return;
        }

        var tokenGroups = buffer.ToStructure<TOKEN_GROUPS>();
        for (var i = 0; i < tokenGroups.GroupCount; i++)
        {
            var tokenGroup = tokenGroups.Groups [i];
            var thisSid = new SecurityIdentifier(tokenGroup.Sid.GetBinaryForm(), 0);
            string accountName = null;
            try
            {
                accountName = thisSid.Translate(typeof(NTAccount)).Value;
            }
            catch
            { }
            Console.WriteLine($"{thisSid} {accountName ?? tokenGroup.ToString()}");
        }

        /*
        try
        { Vanara.PInvoke.Authz.AuthzFreeContext(context); }
        catch
        { ReportLastError("AuthzFreeContext"); }

        try { Vanara.PInvoke.Authz.AuthzFreeResourceManager(rm); }
        catch { ReportLastError("AuthzFreeResourceManager"); }        
        */
    }

    static void ReportLastError(string failedFunction)
    {
        var error = Win32Error.GetLastError();
        Console.WriteLine($"{failedFunction} не удалось выполнить с ошибкой {error}");
    }
}
