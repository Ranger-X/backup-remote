require 'net/ssh'
require 'sshkit'
require 'sshkit/dsl'
require 'sshkit/sudo'


module Backup
  module Remote
    class Command

      include SSHKit::DSL


      def run_ssh_cmd(hostname, ssh_user, ssh_pass, ssh_key, cmd)
        #cmd = "bash -c 'whoami'"

        #puts "run ssh cmd: #{hostname}, #{ssh_user}, #{ssh_pass}, #{cmd}"
        host = SSHKit::Host.new({hostname: hostname, user: ssh_user})
        host.key = ssh_key if ssh_key
        host.password = ssh_pass if ssh_pass

        #srv = ssh_user+'@'+hostname
        all_servers = [host]

        output = ''

        SSHKit::Coordinator.new(host).each in: :sequence do
          output = capture cmd
        end


=begin
        on all_servers do |srv|
          as(user: ssh_user) do
            #execute(cmd)
            output = capture(cmd)
          end
        end
=end

        puts "output: #{output}"

        #
        return {     res: 1,      output: output   }

      rescue => e
        #puts "ssh error: #{e.message}, #{e.backtrace}"

        {
            res: 0,
            output: output,
            error: e.message
        }
      end

      def run_ssh_cmd_sudo(hostname, ssh_user, ssh_pass, ssh_key, cmd, handler=nil)
        host = SSHKit::Host.new("#{ssh_user}@#{hostname}")
        host.key = ssh_key if ssh_key
        host.password = ssh_pass if ssh_pass

        on host do |host|
          execute("#{cmd}", interaction_handler: handler)
        end

        #
        return {res: 1, output: ""}

      rescue => e
        {
            res: 0,
            error: e.message
        }
      end

      def self.interaction_handler_pwd(user, pwd, host='')
        {
            "#{user}@#{host}'s password:" => "#{pwd}\n",
            /#{user}@#{host}'s password: */ => "#{pwd}\n",
            "password: " => "#{pwd}\n",
            "password:" => "#{pwd}\n",
            "Password: " => "#{pwd}\n",
        }
      end



  def ssh_download_file(hostname, ssh_user, ssh_pass, ssh_key, remote_filename, dest_filename)
    return ssh_download_file_sshkit(hostname, ssh_user, ssh_pass, ssh_key, remote_filename, dest_filename)
    #return ssh_download_file_scp(hostname, ssh_user, ssh_pass, remote_filename, dest_filename)
  end

  def ssh_download_file_scp(hostname, ssh_user, ssh_pass, ssh_key, remote_filename, dest_filename)
    Net::SCP.download!(hostname, ssh_user, remote_filename, dest_filename, :ssh => { :password => ssh_pass })

    #
    return {res: 1, output: ""}

  rescue => e
    {
        res: 0,
        error: e.message
    }
  end

  # !! NOT work on big files > 4Gb
  def ssh_download_file_sshkit(hostname, ssh_user, ssh_pass, ssh_key, remote_filename, dest_filename)
    host = SSHKit::Host.new("#{ssh_user}@#{hostname}")
    host.key = ssh_key if ssh_key
    host.password = ssh_pass if ssh_pass

    on host do |host|
      download! remote_filename, dest_filename
    end

    #
    return {res: 1, output: ""}

  rescue => e
    {
        res: 0,
        error: e.message
    }
  end

  def ssh_upload_file(hostname, ssh_user, ssh_pass, ssh_key, source_file, dest_file, handler=nil)
    host = SSHKit::Host.new("#{ssh_user}@#{hostname}")
    host.key = ssh_key if ssh_key
    host.password = ssh_pass if ssh_pass

    # scp
    f_temp = "/tmp/#{SecureRandom.uuid}"

    # sshkit
    SSHKit::Coordinator.new(host).each in: :sequence do
      # upload to temp file
      upload! source_file, f_temp

      # upload to dest
      execute("mv #{f_temp} #{dest_file}", interaction_handler: handler)

    end

=begin
    on host do |host|
      # NOT WORK with sudo
      #upload! source_file, dest_file


      as(user: ssh_user) do
        # upload to temp file
        upload! source_file, f_temp

        # upload to dest
        execute("cp #{f_temp} #{dest_file}", interaction_handler: handler)

      end
    end
=end

    #
    return     {res: 1, output: ""}
  rescue => e
    {
        res: 0,
        error: e.message
    }
  end

end
end
end
