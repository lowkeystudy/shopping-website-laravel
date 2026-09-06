<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnforceAccountStanding
{
    /**
     * Các route được PHÉP truy cập dù chưa xác nhận email / mật khẩu hết hạn
     */
    protected array $exceptRoutes = [
        'verification.notice',
        'verification.verify',
        'verification.send',
        'password.expired',
        'password.expired.update',
        'logout',
        'login',
        'register',
    ];

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        // Chỉ áp dụng cho user ĐÃ đăng nhập, và không đang đứng ở các trang được miễn trừ
        if ($user && !$request->routeIs(...$this->exceptRoutes)) {

            // 1. Kiểm tra đã xác nhận email chưa
            if (method_exists($user, 'hasVerifiedEmail') && !$user->hasVerifiedEmail()) {
                return redirect()->route('verification.notice');
            }

            // 2. Kiểm tra mật khẩu có quá 6 tháng chưa
            if ($user->password_changed_at && $user->password_changed_at->diffInMonths(now()) >= 6) {
                return redirect()->route('password.expired');
            }
        }

        return $next($request);
    }
}
