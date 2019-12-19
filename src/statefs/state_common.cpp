#include <string>
#include <boost/filesystem.hpp>
#include "state_common.hpp"

namespace statefs
{

std::string state_hist_dir;
state_dir_context current_ctx;

void init(const std::string &state_hist_dir_root)
{
    state_hist_dir = realpath(state_hist_dir_root.c_str(), NULL);

    // Initialize 0 state (current state) directory.
    current_ctx = get_state_dir_context(0, true);
}

std::string get_state_dir_root(const int16_t checkpoint_id)
{
    return state_hist_dir + "/" + std::to_string(checkpoint_id);
}

state_dir_context get_state_dir_context(const int16_t checkpoint_id, const bool create_dirs)
{
    state_dir_context ctx;
    ctx.root_dir = get_state_dir_root(checkpoint_id);
    ctx.data_dir = ctx.root_dir + DATA_DIR;
    ctx.block_hashmap_dir = ctx.root_dir + BHMAP_DIR;
    ctx.hashtree_dir = ctx.root_dir + HTREE_DIR;
    ctx.delta_dir = ctx.root_dir + DELTA_DIR;

    if (create_dirs)
    {
        if (!boost::filesystem::exists(ctx.data_dir))
            boost::filesystem::create_directories(ctx.data_dir);
        if (!boost::filesystem::exists(ctx.block_hashmap_dir))
            boost::filesystem::create_directories(ctx.block_hashmap_dir);
        if (!boost::filesystem::exists(ctx.hashtree_dir))
            boost::filesystem::create_directories(ctx.hashtree_dir);
        if (!boost::filesystem::exists(ctx.delta_dir))
            boost::filesystem::create_directories(ctx.delta_dir);
    }

    return ctx;
}

std::string get_relpath(const std::string &fullpath, const std::string &base_path)
{
    std::string relpath = fullpath.substr(base_path.length(), fullpath.length() - base_path.length());
    if (relpath.empty())
        relpath = "/";
    return relpath;
}

std::string switch_base_path(const std::string &fullpath, const std::string &from_base_path, const std::string &to_base_path)
{
    return to_base_path + get_relpath(fullpath, from_base_path);
}

} // namespace statefs