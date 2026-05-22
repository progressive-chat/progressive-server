#pragma once
#include <vector>

#include "types.hpp"

namespace progressive::push {

// 39 base push rules from the Matrix spec
// Organized by priority class buckets

const std::vector<PushRule>& base_prepend_override_rules();
const std::vector<PushRule>& base_append_override_rules();
const std::vector<PushRule>& base_append_content_rules();
const std::vector<PushRule>& base_append_postcontent_rules();
const std::vector<PushRule>& base_append_underride_rules();

const std::vector<PushRule>& all_base_rules();

}  // namespace progressive::push
