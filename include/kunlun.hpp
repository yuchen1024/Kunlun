/****************************************************************************
this hpp implements some routine algorithms
*****************************************************************************
* @author     This file is part of Kunlun, developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#ifndef KUNLUN_HPP_
#define KUNLUN_HPP_

#include "../crypto/global.hpp"
#include "../crypto/bigint.hpp"
#include "../crypto/ec_point.hpp"
#include "../crypto/block.hpp"
#include "../crypto/aes.hpp"
#include "../crypto/prg.hpp"
#include "../crypto/hash.hpp"

#include "../netio/stream_channel.hpp"

#include "../utility/bit_operation.hpp"
#include "../utility/murmurhash2.hpp"
#include "../utility/murmurhash3.hpp"
#include "../utility/polymul.hpp"
#include "../utility/print.hpp"
#include "../utility/routines.hpp"
#include "../utility/serialization.hpp"

namespace kunlun{
    using Serialization::operator<<;
    using Serialization::operator>>;
}

using namespace kunlun;
  
#endif

