//  tagged pointer, for aba prevention
//
//  Copyright (C) 2008, 2009, 2016 Tim Blechmann, based on code by Cory Nelson
//
//  Distributed under the Boost Software License, Version 1.0. (See
//  accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_LOCKFREE_TAGGED_PTR_PTRCOMPRESSION_HPP_INCLUDED
#define BOOST_LOCKFREE_TAGGED_PTR_PTRCOMPRESSION_HPP_INCLUDED

#include <cstdint>
#include <limits>

#include <boost/lockfree/detail/prefix.hpp>

namespace boost { namespace lockfree { namespace detail {

#ifdef BOOST_LOCKFREE_PTR_COMPRESSION

template < class T >
class tagged_ptr
{
    typedef std::uint64_t compressed_ptr_t;

public:
    typedef std::uint16_t tag_t;

private:
    union cast_unit
    {
        compressed_ptr_t value;
        tag_t            tag[ 4 ];
    };

    static constexpr int              tag_index = 3;
    static constexpr compressed_ptr_t ptr_mask  = 0xffffffffffffUL; //(1L<<48L)-1;

    static T* extract_ptr( volatile compressed_ptr_t const& i )
    {
        return (T*)( i & ptr_mask );
    }

    static tag_t extract_tag( volatile compressed_ptr_t const& i )
    {
        cast_unit cu;
        cu.value = i;
        return cu.tag[ tag_index ];
    }

    static compressed_ptr_t pack_ptr( T* ptr, tag_t tag )
    {
        cast_unit ret;
        ret.value            = compressed_ptr_t( ptr );
        ret.tag[ tag_index ] = tag;
        return ret.value;
    }

public:
    /** uninitialized constructor */
    tagged_ptr( void ) noexcept //: ptr(0), tag(0)
    {}

    /** copy constructor */
    tagged_ptr( tagged_ptr const& p ) = default;

    explicit tagged_ptr( T* p, tag_t t = 0 ) :
        ptr( pack_ptr( p, t ) )
    {}

    /** unsafe set operation */
    /* @{ */
    tagged_ptr& operator=( tagged_ptr const& p ) = default;

    void set( T* p, tag_t t )
    {
        ptr = pack_ptr( p, t );
    }
    /* @} */

    /** comparing semantics */
    /* @{ */
    bool operator==( volatile tagged_ptr const& p ) volatile const
    {
        return ( ptr == p.ptr );
    }

    bool operator!=( volatile tagged_ptr const& p ) volatile const
    {
        return !operator==( p );
    }
    /* @} */

    /** pointer access */
    /* @{ */
    T* get_ptr() const
    {
        return extract_ptr( ptr );
    }

    void set_ptr( T* p )
    {
        tag_t tag = get_tag();
        ptr       = pack_ptr( p, tag );
    }
    /* @} */

    /** tag access */
    /* @{ */
    tag_t get_tag() const
    {
        return extract_tag( ptr );
    }

    tag_t get_next_tag() const
    {
        tag_t next = ( get_tag() + 1u ) & ( std::numeric_limits< tag_t >::max )();
        return next;
    }

    void set_tag( tag_t t )
    {
        T* p = get_ptr();
        ptr  = pack_ptr( p, t );
    }
    /* @} */

    /** smart pointer support  */
    /* @{ */
    T& operator*() const
    {
        return *get_ptr();
    }

    T* operator->() const
    {
        return get_ptr();
    }

    operator bool( void ) const
    {
        return get_ptr() != 0;
    }
    /* @} */

protected:
    compressed_ptr_t ptr;
};
#else
#    error unsupported platform
#endif

}}}    // namespace boost::lockfree::detail

#endif /* BOOST_LOCKFREE_TAGGED_PTR_PTRCOMPRESSION_HPP_INCLUDED */
