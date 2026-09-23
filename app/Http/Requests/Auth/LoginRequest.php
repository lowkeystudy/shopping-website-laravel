<?php

namespace App\Http\Requests\Auth;

use Illuminate\Auth\Events\Lockout;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class LoginRequest extends FormRequest
{
    /**
     * GIAI ĐOẠN 0: CẤP QUYỀN TRUY CẬP REQUEST (AUTHORIZATION)
     * Cho phép mọi client (khách vãng lai) gửi request đăng nhập.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * GIAI ĐOẠN 1: TIỀN KIỂM TRA DỮ LIỆU ĐẦU VÀO (INPUT VALIDATION)
     * Laravel tự động chạy hàm này đầu tiên.
     * Chống: Type Confusion, Array Injection và loại bỏ request rác trước khi chạm DB.
     *
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'email' => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ];
    }

    /**
     * GIAI ĐOẠN 2 & 3: LUỒNG ĐIỀU PHỐI XÁC THỰC CHÍNH (AUTHENTICATION PIPELINE)
     * Được Controller gọi sau khi dữ liệu đã vượt qua Giai đoạn 1.
     *
     * @throws ValidationException
     */
    public function authenticate(): void
    {
        // 2.1. Kiểm tra chốt chặn Brute-force trước khi truy vấn DB
        $this->ensureIsNotRateLimited();

        // 3.1. Whitelist tham số đầu vào ($this->only) -> Chống Mass Assignment
        // 3.2. Truy vấn bằng PDO Parameter Binding -> Chống SQL Injection
        // 3.3. So khớp hash một chiều (Hash::check) -> Bảo vệ mật khẩu
        if (! Auth::attempt($this->only('email', 'password'), $this->boolean('remember'))) {
            // Sai mật khẩu: Ghi nhận 1 lần vi phạm vào bộ nhớ đệm
            RateLimiter::hit($this->throttleKey());

            throw ValidationException::withMessages([
                'email' => trans('auth.failed'),
            ]);
        }

        // GIAI ĐOẠN 4: DỌN DẸP VI PHẠM (CLEANUP)
        // Đăng nhập thành công -> Reset toàn bộ biến đếm thử sai
        RateLimiter::clear($this->throttleKey());
    }

    /**
     * HÀM BỔ TRỢ 1: KIỂM SOÁT TẦN SUẤT THỬ SAI (RATE LIMITING CHECK)
     * Được gọi bởi authenticate() ở Giai đoạn 2.
     *
     * @throws ValidationException
     */
    public function ensureIsNotRateLimited(): void
    {
        // Kiểm tra trong Cache/Redis xem đã vượt quá 5 lần thử sai chưa
        if (! RateLimiter::tooManyAttempts($this->throttleKey(), 5)) {
            return;
        }

        // Kích hoạt Event để ghi nhận Audit Log
        event(new Lockout($this));

        // Lấy thời gian còn lại (giây) phải chờ
        $seconds = RateLimiter::availableIn($this->throttleKey());

        // Chặn request và trả lỗi 422 mà không truy vấn DB
        throw ValidationException::withMessages([
            'email' => trans('auth.throttle', [
                'seconds' => $seconds,
                'minutes' => ceil($seconds / 60),
            ]),
        ]);
    }

    /**
     * HÀM BỔ TRỢ 2: ĐỊNH DANH DẤU VÂN TAY TRUY VẤN (THROTTLE FINGERPRINT)
     * Được gọi bởi ensureIsNotRateLimited() và authenticate().
     * Kết hợp Email (chữ thường) + IP nguồn để khoanh vùng mục tiêu tấn công.
     */
    public function throttleKey(): string
    {
        return Str::transliterate(Str::lower($this->string('email')).'|'.$this->ip());
    }
}
