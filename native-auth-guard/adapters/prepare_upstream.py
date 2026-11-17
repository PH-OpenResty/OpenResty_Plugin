#!/usr/bin/env python3
"""Produce a version-checked application patch without modifying its checkout."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def replace(text, before, after):
    if text.count(before) != 1:
        raise ValueError('upstream hook does not occur exactly once')
    return text.replace(before, after)


def imported(text, package):
    return replace(text, 'import (\n', 'import (\n\tauthguard "' + package + '/internal/scdnauth"\n')


def changes(application, sources):
    out = dict(sources)
    if application == 'sub2api':
        base, package = 'backend/', 'github.com/Wei-Shaw/sub2api'
        path = base + 'internal/server/routes/auth.go'
        out[path] = replace(out[path], '\tauth.Use(servermiddleware.BackendModeAuthGuard(settingService))',
            '\tauth.Use(installSCDNAuth(v1, settingService))\n\tauth.Use(servermiddleware.BackendModeAuthGuard(settingService))')
        path = base + 'internal/service/auth_service.go'
        text = imported(out[path], package)
        text = replace(text, '\t// 检查是否需要邮件验证\n', '\tverifiedMailbox := false\n\t// 检查是否需要邮件验证\n')
        anchor = '\t\tif err := s.emailService.VerifyCode(ctx, email, verifyCode); err != nil {\n\t\t\treturn "", nil, fmt.Errorf("verify code: %w", err)\n\t\t}\n'
        text = replace(text, anchor, anchor + '\t\tverifiedMailbox = true\n')
        anchor = '\tif err := s.createUserAndClaimInvitation(ctx, user, invitationRedeemCode); err != nil {'
        text = replace(text, anchor, '\tif err := authguard.RequireCreate(ctx,email,password,verifiedMailbox); err != nil {\n\t\treturn "",nil,infraerrors.Forbidden("AUTH_GUARD_REJECTED", "registration did not meet the authentication policy")\n\t}\n' + anchor)
        text = replace(text, '\ts.postAuthUserBootstrap(ctx, user, "email", true)', '\tauthguard.Report(ctx,"registration_complete")\n\ts.postAuthUserBootstrap(ctx, user, "email", true)')
        text = replace(text, '\t\tif err := s.emailService.VerifyCode(ctx, email, verifyCode); err != nil {', '\t\tif err := s.emailService.VerifyCode(ctx, email, verifyCode); err != nil {\n\t\t\tif errors.Is(err,ErrInvalidVerifyCode) { authguard.Report(ctx,"invalid_email_code") }')
        out[path] = text
        path = base + 'internal/repository/user_repo.go'
        text = imported(out[path], package)
        anchor = 'func (r *userRepository) create(ctx context.Context, userIn *service.User, guardEmailAlias bool, domainLimit string) error {\n'
        text = replace(text, anchor, anchor + '\tif userIn != nil { if err:=authguard.CheckInsert(ctx,userIn.Email); err!=nil { return err } }\n')
        out[path] = text
        path = base + 'internal/handler/auth_handler.go'
        text = imported(out[path], package)
        text = replace(text, '\t"context"\n', '\t"context"\n\t"errors"\n')
        anchor = '\ttoken, user, err := h.authService.Login(c.Request.Context(), req.Email, req.Password)\n\tif err != nil {\n'
        text = replace(text, anchor, anchor + '\t\tif errors.Is(err,service.ErrInvalidCredentials) { authguard.Report(c.Request.Context(),"invalid_credentials") }\n')
        text = replace(text, '\t\tresponse.Success(c, TotpLoginResponse{', '\t\tauthguard.Report(c.Request.Context(),"primary_ok_requires_verification")\n\t\tresponse.Success(c, TotpLoginResponse{')
        anchor = '\tif err := h.totpService.VerifyCode(c.Request.Context(), session.UserID, req.TotpCode); err != nil {\n'
        text = replace(text, anchor, anchor + '\t\tif errors.Is(err,service.ErrTotpInvalidCode) { authguard.Report(c.Request.Context(),"invalid_second_factor") }\n')
        # Both the regular token-pair and its existing fallback success branch.
        anchor = '\t\tresponse.Success(c, AuthResponse{'
        text = replace(text, anchor, '\t\tauthguard.Report(c.Request.Context(),"login_complete")\n' + anchor)
        anchor = '\tresponse.Success(c, AuthResponse{'
        # Do not accidentally match the extra tab in the fallback branch.
        text = replace(text, '\n' + anchor, '\n\tauthguard.Report(c.Request.Context(),"login_complete")\n' + anchor)
        text = text.replace('ip.GetClientIP(c)', 'authguard.ClientIP(c.Request.Context(),ip.GetClientIP(c))')
        out[path] = text
        helper = base + 'internal/server/routes/scdn_auth_guard.go'
    else:
        base, package = '', 'github.com/QuantumNous/new-api'
        path = 'router/api-router.go'
        out[path] = replace(out[path], '\tapiRouter := router.Group("/api")', '\tapiRouter := router.Group("/api")\n\tcontroller.InstallSCDNAuth(apiRouter)')
        path = 'controller/user.go'
        text = imported(out[path], package)
        anchor = '\t\tcase errors.Is(err, model.ErrUserEmptyCredentials):'
        text = replace(text, anchor, '\t\tcase errors.Is(err, model.ErrInvalidCredentials):\n\t\t\tauthguard.Report(c.Request.Context(),"invalid_credentials")\n\t\t\tcommon.ApiErrorT(c, "Username or password is incorrect, or user has been banned")\n' + anchor)
        text = replace(text, '\tif challenge != nil {\n', '\tif challenge != nil {\n\t\tauthguard.Report(c.Request.Context(),"primary_ok_requires_verification")\n')
        text = replace(text, 'func writeLoginResponse(c *gin.Context, user *model.User, bundle *service.AuthBundle) {\n', 'func writeLoginResponse(c *gin.Context, user *model.User, bundle *service.AuthBundle) {\n\tauthguard.Report(c.Request.Context(),"login_complete")\n')
        anchor = '\tif common.EmailVerificationEnabled {\n\t\tif user.Email == ""'
        text = replace(text, anchor, '\tverifiedMailbox := false\n' + anchor)
        anchor = '\t\tif !common.VerifyCodeWithKey(user.Email, user.VerificationCode, common.EmailVerificationPurpose) {\n'
        text = replace(text, anchor, anchor + '\t\t\tauthguard.Report(c.Request.Context(),"invalid_email_code")\n')
        anchor = '\t\tif err := model.EnsureEmailAvailable(user.Email, 0); err != nil {'
        text = replace(text, anchor, '\t\tverifiedMailbox = true\n' + anchor)
        anchor = '\tif err := cleanUser.Insert(inviterId); err != nil {'
        text = replace(text, anchor, '\tif err:=authguard.RequireCreate(c.Request.Context(),user.Email,user.Password,verifiedMailbox); err!=nil { common.ApiError(c,err);return }\n' + anchor)
        text = replace(text, '\t// 获取插入后的用户ID', '\tauthguard.Report(c.Request.Context(),"registration_complete")\n\t// 获取插入后的用户ID')
        text = text.replace('c.ClientIP()', 'authguard.ClientIP(c.Request.Context(),c.ClientIP())')
        out[path] = text
        path = 'controller/login_verification.go'
        text = imported(out[path], package)
        text = replace(text, '\t"encoding/json"\n', '\t"encoding/json"\n\t"errors"\n')
        anchor = '\tbundle, migration, err := service.VerifyLoginCode(request.FlowToken, request.Code, c.ClientIP(), c.Request.UserAgent())\n\tif err != nil {\n'
        text = replace(text, anchor, anchor + '\t\tif errors.Is(err,service.ErrVerificationFailed) { authguard.Report(c.Request.Context(),"invalid_second_factor") }\n')
        text = text.replace('c.ClientIP()', 'authguard.ClientIP(c.Request.Context(),c.ClientIP())')
        out[path] = text
        path = 'controller/oauth.go'
        text = imported(out[path], package)
        anchor = '\t// Use transaction to ensure user creation and OAuth binding are atomic'
        hook = '''\tverifiedMailbox := false
\tif emailProvider,ok:=provider.(oauth.VerifiedEmailProvider); ok && user.Email!="" {
\t\temails,err:=emailProvider.GetVerifiedEmails(c.Request.Context(),token)
\t\tif err!=nil { return nil,nil,err }
\t\tverifiedMailbox=slices.ContainsFunc(emails,func(email string)bool{return model.NormalizeEmail(email)==model.NormalizeEmail(user.Email)})
\t}
\tif err:=authguard.RequireCreate(c.Request.Context(),user.Email,"",verifiedMailbox); err!=nil { return nil,nil,err }
'''
        text = replace(text, anchor, hook + anchor)
        text = text.replace('c.ClientIP()', 'authguard.ClientIP(c.Request.Context(),c.ClientIP())')
        out[path] = text
        path = 'controller/wechat.go'
        text = imported(out[path], package)
        anchor = '\t\t\tif err := user.Insert(0); err != nil {'
        text = replace(text, anchor, '\t\t\tif err:=authguard.RequireCreate(c.Request.Context(),user.Email,"",false); err!=nil { common.ApiError(c,err);return }\n' + anchor)
        out[path] = text
        helper = 'controller/scdn_auth_guard.go'
    out[helper] = (HERE/'templates'/f'{application}.go.in').read_text() + (HERE/'templates/gin.go.in').read_text()
    for name in ('guard.go', 'application.go'):
        out[base + 'internal/scdnauth/' + name] = (HERE/'go'/name).read_text()
    return out


def prepare(application, source, gofmt):
    manifest = json.loads((HERE/'upstream-lock.json').read_text())[application]
    original = {}
    for entry in manifest['files']:
        path, digest = entry['path'], entry['sha256']
        target = (source/path).resolve()
        if not target.is_relative_to(source.resolve()):
            raise ValueError('source path escaped the requested checkout')
        raw = target.read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('upstream file changed: ' + path)
        original[path] = raw.decode('utf-8')
    modified = changes(application, original)
    patch = []
    for path, text in sorted(modified.items()):
        if path.endswith('.go'):
            result = subprocess.run([gofmt], input=text, capture_output=True, text=True, encoding='utf-8', check=True, timeout=30)
            text = result.stdout
        before = original.get(path, '')
        if text == before:
            continue
        patch.extend(difflib.unified_diff(before.splitlines(True), text.splitlines(True),
            fromfile='a/'+path if path in original else '/dev/null', tofile='b/'+path))
    return ''.join(patch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application', choices=['sub2api', 'newapi'], required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gofmt', default=shutil.which('gofmt'))
    args = parser.parse_args()
    try:
        if not args.gofmt or args.output.resolve().is_relative_to(args.source.resolve()):
            raise ValueError('use an external patch output path and a local gofmt executable')
        patch = prepare(args.application, args.source, args.gofmt)
        with args.output.open('w', encoding='utf-8', newline='\n') as output:
            output.write(patch)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, 'application patch failed: ' + str(error) + '\n')
    print(json.dumps({'prepared': True, 'checkout_modified': False, 'application': args.application}))


if __name__ == '__main__':
    main()
