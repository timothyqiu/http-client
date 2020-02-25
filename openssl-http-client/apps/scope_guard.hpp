#ifndef OHC_APP_SCOPE_GUARD_HPP_
#define OHC_APP_SCOPE_GUARD_HPP_

#include <functional>

// Utility to call the lambda at scope exit

template<typename F>
class ScopeGuard {
public:
    explicit ScopeGuard(F&& f)
        : func_{std::move(f)}
    {
    }

    ~ScopeGuard()
    {
        func_();
    }

    ScopeGuard(ScopeGuard const&) = delete;
    ScopeGuard& operator=(ScopeGuard const&) = delete;

private:
    std::function<void()> func_;
};

#define CONCAT_IMPL(a, b) a ## b
#define CONCAT(a, b) CONCAT_IMPL(a, b)
#define SCOPE_EXIT(f) ScopeGuard CONCAT(guard_,__LINE__){f}

#endif  // OHC_APP_SCOPE_GUARD_HPP_
