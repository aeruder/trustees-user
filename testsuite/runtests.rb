#!/usr/bin/env ruby

# This is the trustees testsuite driver.
#
# See README for a description of what this
# program is doing.

require 'find'

# This matches comments and blank lines
CommentRegex = /^\s*(#.*)*$/

# settrustees binary
TrusteesBinary = File.join("..", "src", "settrustees")

class ParseError < Exception
end

# These are the actual 'tXXX/scenario' operations.
module TestFunctions
  def self.read(passwd, filesystem, file)
    file = filesystem.make_absolute(file)
    $stderr.puts "read #{file} as #{passwd.user_for_uid(Process.euid)}"
    File.open(file, "r") { |io| }
    true
  end
  def self.opendir(passwd, filesystem, file)
    file = filesystem.make_absolute(file)
    $stderr.puts "opendir #{file} as #{passwd.user_for_uid(Process.euid)}"
    Dir.open(file) { |io| }
    true
  end
  def self.write(passwd, filesystem, file)
    file = filesystem.make_absolute(file)
    $stderr.puts "touch #{file} as #{passwd.user_for_uid(Process.euid)}"
    File.open(file, "w") { |io| }
    true
  end
  def self.mkdir(passwd, filesystem, file)
    file = filesystem.make_absolute(file)
    $stderr.puts "mkdir #{file} as #{passwd.user_for_uid(Process.euid)}"
    Dir.mkdir(file)
    true
  end
  def self.rmdir(passwd, filesystem, file)
    file = filesystem.make_absolute(file)
    $stderr.puts "rmdir #{file} as #{passwd.user_for_uid(Process.euid)}"
    Dir.rmdir(file)
    true
  end
  def self.unlink(passwd, filesystem, file)
    file = filesystem.make_absolute(file)
    $stderr.puts "unlink #{file} as #{passwd.user_for_uid(Process.euid)}"
    File.unlink(file)
    true
  end
  def self.rename(passwd, filesystem, old, new)
    old = filesystem.make_absolute(old)
    new = filesystem.make_absolute(new)
    $stderr.puts "rename #{old} #{new} as #{passwd.user_for_uid(Process.euid)}"
    File.rename(old, new)
    true
  end
  def self.link(passwd, filesystem, old, new)
    old = filesystem.make_absolute(old)
    new = filesystem.make_absolute(new)
    $stderr.puts "ln #{old} #{new} as #{passwd.user_for_uid(Process.euid)}"
    File.link(old, new)
    true
  end
end

# UsersAndGroups handles the 'passwd' file.  It is responsible for loading the
# file and providing methods to make looking up uid's/gid's for users/groups
# easier.
class UsersAndGroups
  def initialize(config, start_uid = 100000, start_gid = 100000)
    @users = Hash.new [start_uid, []]
    @groups = Hash.new start_gid
    @current_gid = start_uid+1
    @current_uid = start_gid+1

    File.open(config, "r") { |io|

      io.each_with_index { |line, index|
        line.strip!
        line.gsub! /\s+/, ""

        case line
          when CommentRegex:
          when /^\w+$/:
            add_user line
          when /^:([\w,]+)$/:
            $1.split(",").reject { |key| key.empty? }.each { |group|
              add_group group
            }
          when /^(\w+):([\w,]+)$/:
            user,groups = $1,$2
            add_user user
            groups.split(",").reject { |key| key.empty? }.each { |group|
              add_group group
              add_user_to_group user, group
            }
          else
            raise ParseError.new("#{config}:#{index+1} parse error")
        end
      }
    }
  end

  def gid_for_group(group)
    @groups[group]
  end

  def uid_for_user(user)
    @users[user][0]
  end

  def user_for_uid(uid)
    @users.each_key { |key| @users[key][0] == uid and return key }
  end

  def groups_for_user(user)
    @users[user][1]
  end

  def group_for_gid(gid)
    @groups.each_key { |key| @groups[key] == gid and return key }
  end

  def add_group(group)
    if not @groups.has_key? group then
      @groups[group] = @current_gid
      @current_gid += 1
    end
    @groups[group]
  end

  def add_user(user)
    if not @users.has_key? user then
      @users[user] = [@current_uid, []]
      @current_uid += 1
    end
    @users[user]
  end

  def add_user_to_group(user, group)
    userinfo = add_user user
    add_group group
    userinfo[1].push group
  end

  def users
    @users.keys
  end

  def groups
    @groups.keys
  end

  def to_s
    str = ""
    str << "Users: " << @users.keys.sort.join(", ") << "\n"
    str << "Groups: " << @groups.keys.sort.join(", ") << "\n"
  end
end

# Handles the 'filesystem' file.  Has methods to both create the fake chroot
# and destroy it.
class Filesystem
  attr_reader :directory

  def initialize(config, dir)
    @directory = dir
    @entries = []
    if @directory =~ /[\/\.]/ or @directory.empty? then
      raise "Filesystem directory cannot contain . or /"
    end
    File.open(config, "r") { |io|
      io.each_with_index { |line, index|
        line.strip!

        case line
          when CommentRegex:
          when /^(\/[\/\w_-]*)\s+([0-7]+)\s+(\w+)\s+(\w+)$/:
            @entries.push( {
              :entry => $1,
              :mode => $2.to_i(8),
              :user => $3,
              :group => $4
            })
          else
            raise ParseError.new("#{config}:#{index+1} parse error")
        end
      }
    }
  end

  def teardown
    if File.exists? @directory and not File.directory? @directory then
      raise "Something exists at '#{@directory}' but it isn't a file..."
    end
    if File.directory? @directory then
      allpaths = []
      Find.find(@directory) { |path| allpaths.push(path) }
      allpaths.sort { |a, b| b.length <=> a.length }.each { |path|
        if File.directory? path then
          Dir.rmdir path
        else
          File.unlink path
        end
      }
    end
  end

  def setup(passwd)
    if File.exists? @directory then
      raise "Something exists at '#{@directory} already..."
    end

    @entries.each { |x|
      entry = File.join(@directory, x[:entry])
      owner = passwd.uid_for_user(x[:user])
      group = passwd.gid_for_group(x[:group])
      mode = x[:mode]

      if entry =~ /\/$/ then
        Dir.mkdir(entry)
      else
        File.open(entry, "w") { |io| }
      end
      File.chmod(mode, entry)
      File.chown(owner, group, entry)
    }
  end

  def mountpoint
    if not @mountpoint then
      f = IO.popen("df -P .", "r")
      lines = f.readlines
      f.close

      raise "Confused by `df -P .` output (not 2 lines)" if lines.length != 2

      parts = lines[1].strip.split(/\s+/)
      raise "Confused by `df -P .` output (not 6 fields)" if parts.length != 6

      @device = parts[0]
      @mountpoint = parts[5]
      if Dir.pwd.index(@mountpoint) != 0 then
        raise "Confused by `df -P .` output (not subset of mountpoint)"
      end

      # We cut the mountpoint off the path, if the mountpoint
      # is /, we don't need to cut anything off..
      cutoff = @mountpoint.length
      cutoff = 0 if cutoff == 1

      @trustees_path = Dir.pwd[cutoff..-1]
      if @trustees_path !~ /^\/.*/ or @trustees_path.length <= 1
        raise "Apparently we aren't at a true subset of the mount point?"
      end
      @trustees_path = File.join(@trustees_path, @directory)

      if not File.blockdev? @device then
        raise "Apparently our current device is not a block device?"
      end
    end
    @mountpoint
  end

  def trustees_path
    self.mountpoint
    @trustees_path
  end

  def device
    self.mountpoint
    @device
  end

  def make_absolute(path)
    File.join(Dir.pwd, @directory, path)
  end
end

# Handles the 'tXXX/config' file.  Can convert the tXXX/config into something
# settrustees can understand and send it to the kernel.
class TrusteesConfig
  attr_reader :config
  def initialize(config)
    @config = config
    @entries = []
    File.open(config, "r") { |io|
      io.each_with_index { |line, index|
        line.strip!

        case line
          when CommentRegex:
          when /^(\/[\/\w_-]*):(.*)$/:
            path = $1
            perms = $2.gsub(/\s+/, "").split(/:/)
            if perms.length % 2 != 0 then
              raise ParseError.new("#{config}:#{index+1} parse error")
            end
            every_other=(0...(perms.length/2)).to_a.map { |a| a * 2 }
            users = every_other.map { |a| perms[a] }
            perms = every_other.map { |a| perms[a+1] }
            @entries.push([path, users.zip(perms)])
          else
            raise ParseError.new("#{config}:#{index+1} parse error")
        end
      }
    }
  end
  def send_to_kernel(passwd, filesystem)
    f = IO.popen("#{TrusteesBinary} -f - >&2", "w")
    $stderr.puts "---"
    @entries.each { |entry|
      path, perms = entry
      command = "[#{filesystem.device}]"
      command += File.join(filesystem.trustees_path, path) + ":"
      command += perms.map { |perm|
        user, mode = perm
        if user == "*" then
          # Don't need to do anything, * is ok
        elsif user =~ /^(\+)/ then
          user = $1 + passwd.gid_for_group(user[1..-1]).to_s
        else
          user = passwd.uid_for_user(user)
        end

        "#{user}:#{mode}"
      }.join(":")
      f.puts command
      $stderr.puts command
    }
    $stderr.puts "---"
    f.close
  end
end

# Handles opening a test directory and running a test.
class Test
  def self.test?(dir)
    config = File.join(dir, "config")
    scenario = File.join(dir, "scenario")
    File.directory? dir and File.file? config and File.file? scenario
  end
  def initialize(dir)
    raise "#{dir} is not a test directory" if not Test.test? dir
    @directory = dir
    @scenario = File.join(dir, "scenario")
    @config = TrusteesConfig.new(File.join(dir, "config"))

    @entries = []
    File.open(@scenario, "r") { |io|
      io.each_with_index { |line, index|
        line.strip!

        case line
          when CommentRegex:
          when /^should_(pass|fail)\s+(\w+)\s+(\w+)\s+(.*)/:
            state = ($1 == "pass" ? true : false)
            user,operation = $2, $3
            args=$4.split(/\s+/)
            @entries.push({
              :state => state,
              :user => user,
              :operation => operation,
              :args => args
            })
          else
            raise ParseError.new("#{config}:#{index+1} parse error")
        end
      }
    }
  end
  def handle_entry(entry, passwd, filesystem)
    groups = Process.groups
    usergroups = passwd.groups_for_user(entry[:user])
    $stderr.puts "*** Switching to #{entry[:user]}:#{usergroups.join(",")}"
    $stderr.puts "*** Test: should_#{entry[:state] ? "pass" : "fail" } #{entry[:user]} #{entry[:operation]} #{entry[:args].join(" ")}"
    Process.groups = usergroups.map { |grp| passwd.gid_for_group(grp) }
    Process.euid = passwd.uid_for_user(entry[:user])

    retvalue = false

    begin
      func = entry[:operation].to_sym
      if not TestFunctions.respond_to? func then
        raise ParseError.new("Operation #{func} not found in TestFunctions")
      end
      args = [passwd, filesystem] + entry[:args]
      retvalue = (entry[:state] == TestFunctions.send(func, *args))
    rescue ParseError
      raise $!
    rescue
      retvalue = (entry[:state] == false)
    ensure
      $stderr.puts
      Process.euid = 0
      Process.groups = groups
    end

    retvalue
  end

  def run(passwd, filesystem)
    $stderr.puts "-"*72
    $stderr.puts "Test: #{@directory}"
    $stderr.puts ""
    $stderr.puts "*** Setting up '#{filesystem.directory}'"
    filesystem.setup(passwd)

    $stderr.puts "*** Sending config to kernel module"
    @config.send_to_kernel(passwd, filesystem)
    $stderr.puts

    begin
      @entries.each_with_index { |x, index|
        ret = handle_entry(x, passwd, filesystem)
        if not ret then
          raise "#{@scenario} -- Test \##{index+1} failed"
        end
      }
    ensure
      filesystem.teardown
    end
    true
  end
end


###################
# MAIN
###################

if $0 != "./runtests.rb" then
  raise "#{$0} must be ran as './runtests.rb ...'"
end

if Process.uid != 0 then
  raise "Script must be ran as root"
end

if not File.executable? TrusteesBinary then
  raise "#{TrusteesBinary} does not exist!"
end

$stderr.puts "*** Loading 'passwd' file..."
passwd = UsersAndGroups.new("passwd")

$stderr.puts "*** Loading 'filesystem' file..."
fs = Filesystem.new("filesystem", "filesystem_root")
$stderr.puts "*** \tMount point: #{fs.mountpoint}"
$stderr.puts "*** \tRelative path: #{fs.trustees_path}"
$stderr.puts "*** \tDevice: #{fs.device}"
$stderr.puts


at_exit {
  system("#{TrusteesBinary} -D > /dev/null 2>&1 < /dev/null")
  fs.teardown
}

if ARGV.length == 0 then
  tests = Dir.entries(".").reject { |x| x == "." or x == ".." }.select { |x|
    File.directory? x and Test.test? x
  }.sort { |a, b| a <=> b }
else
  tests = ARGV
end

results = {}
tests.each { |test|
  t = Test.new(test)
  begin
    results[test] = t.run(passwd, fs)
  rescue
    $stderr.puts $!.to_s
    results[test] = false
  end
}

$stderr.puts
$stderr.puts "Summary:"
endresult = true
tests.each { |test|
  puts "#{test}: #{results[test] ? "passed" : "failed"}"
  endresult = false if not results[test]
}

exit endresult

