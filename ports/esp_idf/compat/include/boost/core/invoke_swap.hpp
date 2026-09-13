// Minimal compatibility shim: newer Boost.Geometry (karney_inverse.hpp) calls
// boost::core::invoke_swap(), which apt's libboost-dev 1.83 core headers do
// not yet provide (only the older boost::swap() in <boost/core/swap.hpp>).
// This is intentionally NOT a copy of upstream Boost's invoke_swap.hpp: that
// file redefines the boost_swap_impl::is_const helper that <boost/core/swap.hpp>
// already defines, which collides when both headers end up in one translation
// unit (as happens here, since vanetza/common/position_fix.hpp pulls in
// <boost/optional.hpp> -> <boost/core/swap.hpp> ahead of this one). Building
// invoke_swap on top of the already-available boost::swap() avoids that clash.
#ifndef BOOST_CORE_INVOKE_SWAP_HPP
#define BOOST_CORE_INVOKE_SWAP_HPP

#include <boost/core/swap.hpp>

namespace boost {
namespace core {

template<class T>
inline void invoke_swap(T& left, T& right)
{
    boost::swap(left, right);
}

} // namespace core
} // namespace boost

#endif // BOOST_CORE_INVOKE_SWAP_HPP
