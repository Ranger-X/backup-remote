# encoding: utf-8

module Backup
  module Database
    class PgProbackup < Base
      class Error < Backup::Error; end

      MODES = [ :full, :page, :delta, :ptrack ]
      COMPRESS_ALGORITHMS = [ :zlib, :pglz, :none ]
      REMOTE_PROTOS = [ :none, :ssh ]
      LOG_LEVELS = [ :verbose, :log, :info, :warning, :error, :off ]

      ##
      # Name of the database that pg_probackup should connect.
      # It is recommended from security purposes to use separate database for backup operations.
      attr_accessor :backup_db

      ##
      # Credentials for the specified database
      attr_accessor :username, :password

      ##
      # Connectivity options
      attr_accessor :host, :port, :socket

      ##
      # Backup catalog directory
      attr_accessor :catalog

      ##
      # Instance name in backup catalog
      attr_accessor :name

      ##
      # Backup mode. One of: full, page, delta, ptrack.
      # Default: full
      attr_accessor :mode

      ##
      # Spreads out the checkpoint over a period of time.
      # Default: false. So pg_probackup tries to complete the checkpoint as soon as possible.
      attr_accessor :smooth_checkpoint

      ##
      # Includes the log directory into the backup. This directory usually contains log messages.
      # Default: false
      attr_accessor :backup_pg_log

      ##
      # Sets in seconds the timeout for WAL segment archiving and streaming.
      # Default: 300
      attr_accessor :archive_timeout

      ##
      # Disables block-level checksum verification to speed up backup.
      # Default: false
      attr_accessor :skip_block_validation

      ##
      # Skips automatic validation after successfull backup. You can use this flag if you validate backups regularly and would like to save time when running backup operations.
      # Default: false
      attr_accessor :no_validate

      ##
      # Backup threads count. Default: 1
      attr_accessor :threads

      ##
      # STREAM is the optional WAL delivery mode. Default: false
      attr_accessor :stream_mode

      ##
      # To back up a directories located outside of the data directory
      attr_accessor :external_dirs

      ##
      # Defines the algorithm to use for compressing data files. Possible values are zlib, pglz, and none. If set to zlib or pglz, this option enables compression.
      # Default: none
      attr_accessor :compress_algorithm

      ##
      # Defines compression level (0 through 9, 0 being no compression and 9 being best compression)
      # Default: 1
      attr_accessor :compress_level

      ##
      # Specifies the protocol to use for remote operations. Currently only the SSH protocol is supported. Possible values are:
      # ssh enables the remote backup mode via SSH.
      # none explicitly disables the remote mode.
      # Default: none
      attr_accessor :remote_proto

      ##
      # Specifies the remote host IP address or hostname to connect to.
      attr_accessor :remote_host

      ##
      # Specifies the remote host port to connect to.
      # Default: 22
      attr_accessor :remote_port

      ##
      # Specifies remote host user for SSH connection. If you omit this option, the current user initiating the SSH connection is used.
      attr_accessor :remote_user

      ##
      # Specifies pg_probackup installation directory on the remote system.
      attr_accessor :remote_path

      ##
      # Specifies a string of SSH command-line options.
      # For example, the following options can used to set keep-alive for ssh connections opened by pg_probackup:
      # '-o ServerAliveCountMax=5 -o ServerAliveInterval=60'
      attr_accessor :remote_ssh_options

      ##
      # Specifies the number of full backup copies to keep in the data directory. Must be a positive integer. The zero value disables this setting.
      # Default: 0
      attr_accessor :retention_redundancy

      ##
      # Number of days of recoverability. Must be a positive integer. The zero value disables this setting.
      # Default: 0
      attr_accessor :retention_window

      ##
      # Number of latest valid backups on every timeline that must retain the ability to perform PITR. Must be a positive integer. The zero value disables this setting.
      # Default: 0
      attr_accessor :retention_wal_depth

      ##
      # Deletes WAL files that are no longer required to restore the cluster from any of the existing backups.
      # Default: false
      attr_accessor :retention_delete_wal

      ##
      # Deletes backups that do not conform to the retention policy defined in the pg_probackup.conf configuration file.
      # Default: false
      attr_accessor :retention_delete_expired

      ##
      # Merges the oldest incremental backup that satisfies the requirements of retention policy with its parent backups that have already expired.
      # Default: false
      attr_accessor :retention_merge_expired

      ##
      # Displays the current status of all the available backups, without deleting or merging expired backups, if any.
      # Default: false
      attr_accessor :retention_dry_run

      ##
      # Specifies the amount of time the backup should be pinned. Must be a positive integer. The zero value unpin already pinned backup.
      # Supported units: ms, s, min, h, d (s by default).
      # Example: 30d
      attr_accessor :pinning_ttl

      ##
      # Specifies the timestamp up to which the backup will stay pinned. Must be a ISO-8601 complaint timestamp.
      # Example: '2020-01-01 00:00:00+03'
      attr_accessor :pinning_expire_time

      ##
      # Controls which message levels are sent to the console log. Valid values are verbose, log, info, warning, error and off.
      # Each level includes all the levels that follow it. The later the level, the fewer messages are sent. The off level disables console logging.
      # Default: info
      attr_accessor :log_level_console

      ##
      # Controls which message levels are sent to a log file. Valid values are verbose, log, info, warning, error and off.
      # Each level includes all the levels that follow it. The later the level, the fewer messages are sent. The off level disables file logging.
      # Default: off
      attr_accessor :log_level_file

      ##
      # Defines the filenames of the created log files. The filenames are treated as a strftime pattern, so you can use %-escapes to specify time-varying filenames.
      #
      # For example, if you specify the 'pg_probackup-%u.log' pattern, pg_probackup generates a separate log file for each day of the week, with %u replaced by the corresponding decimal number: pg_probackup-1.log for Monday, pg_probackup-2.log for Tuesday, and so on.
      #
      # This option takes effect if file logging is enabled by the log-level-file option.
      # Default: 'pg_probackup.log'
      attr_accessor :log_filename

      ##
      # Defines the filenames of log files for error messages only. The filenames are treated as a strftime pattern, so you can use %-escapes to specify time-varying filenames.
      #
      # For example, if you specify the 'error-pg_probackup-%u.log' pattern, pg_probackup generates a separate log file for each day of the week, with %u replaced by the corresponding decimal number: error-pg_probackup-1.log for Monday, error-pg_probackup-2.log for Tuesday, and so on.
      #
      # This option is useful for troubleshooting and monitoring.
      attr_accessor :error_log_filename

      ##
      # Defines the directory in which log files will be created. You must specify the absolute path. This directory is created lazily, when the first log message is written.
      # Default: $BACKUP_PATH/log/
      attr_accessor :log_directory

      ##
      # Maximum size of an individual log file. If this value is reached, the log file is rotated once a pg_probackup command is launched, except help and version commands. The zero value disables size-based rotation.
      # Supported units: kB, MB, GB, TB (kB by default).
      # Default: 0
      attr_accessor :log_rotation_size

      ##
      # Maximum lifetime of an individual log file. If this value is reached, the log file is rotated once a pg_probackup command is launched, except help and version commands. The time of the last log file creation is stored in $BACKUP_PATH/log/log_rotation. The zero value disables time-based rotation.
      # Supported units: ms, s, min, h, d (min by default).
      # Default: 0
      attr_accessor :log_rotation_age

      ##
      # Additional "pg_probackup" options
      attr_accessor :additional_options

      ##
      # If set the pg_probackup command is executed as the given user
      attr_accessor :sudo_user

      def initialize(model, database_id = nil, &block)
        super
        instance_eval(&block) if block_given?

        @mode                     ||= :full
        @stream_mode              ||= false
        @threads                  ||= 1
        @smooth_checkpoint        ||= false
        @backup_pg_log            ||= false
        @archive_timeout          ||= 300
        @skip_block_validation    ||= false
        @compress_algorithm       ||= :none
        @compress_level           ||= 1
        @remote_proto             ||= :none
        @remote_port              ||= 22
        @retention_redundancy     ||= 0
        @retention_window         ||= 0
        @retention_wal_depth      ||= 0
        @retention_delete_wal     ||= false
        @retention_delete_expired ||= false
        @retention_merge_expired  ||= false
        @retention_dry_run        ||= false
        @log_level_console        ||= :info
        @log_level_file           ||= :off

        required = [ :backup_db, :catalog, :name, :username ]

        validate_param_array(:mode, MODES)

        if threads.to_i <= 0 || threads.to_i > 24
          raise Error, "Thread count (#{threads}) is invalid. Must be greater than 0 and less than 25"
        end

        if archive_timeout.to_i <= 0
          raise Error, "Archive timeout (#{archive_timeout}) must be greater than 0"
        end

        validate_param_array(:compress_algorithm, COMPRESS_ALGORITHMS)

        if compress_level.to_i < 0 || compress_level.to_i > 9
          raise Error, "Compression level (#{compress_level}) is invalid. Must be between 0 and 9"
        end

        validate_param_array(:remote_proto, REMOTE_PROTOS)

        unless remote_proto.to_sym == :none
          required += [ :remote_host, :remote_user, :remote_path ]
        end

        [ :retention_redundancy, :retention_window, :retention_wal_depth ].each do |opt|
          v = self.send(opt).to_i
          raise Error, "Value for option '#{opt}' (#{v}) must be between 0 and 100." unless v >= 0 && v <= 100
        end

        validate_param_array(:log_level_console, LOG_LEVELS)
        validate_param_array(:log_level_file, LOG_LEVELS)

        # TODO: check for pinning_expire_time format (and for is_a?(DateTime) maybe?)

        required.each do |opt|
          raise Error, "Option '#{opt}' is required." if self.send(opt).to_s.empty?
        end
      end

      def validate_param_array(param_name, valid_values)
        v = self.send(param_name.to_sym)

        if v.nil? || !valid_values.include?(v.to_sym)
          raise Error, "Parameter #{param_name.to_s} with value '#{v.to_s}' is invalid. You must choose one of: #{valid_values.join(', ')}"
        end
      end

      ##
      # Performs the pg_probackup backup.
      def perform!
        super

        pipeline = Pipeline.new

        pipeline << pg_probackup_cmd

        pipeline.run
        if pipeline.success?
          log!(:finished)
        else
          raise Error, "Backup failed!\n" + pipeline.error_messages
        end
      end

      def pg_probackup_cmd
        #pg_probackup backup -B backup_dir -b backup_mode --instance instance_name
        # [--help] [-j num_threads] [--progress]
        # [-C] [--stream [-S slot_name] [--temp-slot]] [--backup-pg-log]
        # [--no-validate] [--skip-block-validation]
        # [-w --no-password] [-W --password]
        # [--archive-timeout=timeout] [--external-dirs=external_directory_path]
        # [connection_options] [compression_options] [remote_options]
        # [retention_options] [pinning_options] [logging_options]
        "#{ sudo_option } #{ password_env }".lstrip +
        "#{ utility(:pg_probackup) } backup #{ backup_catalog_option } #{ mode_option } #{ instance_name } " +
        "#{ threads_option } #{ smooth_checkpoint_option } #{ stream_mode_option } #{ backup_pg_log_option } " +
        "#{ no_validate_option } #{ skip_block_validation_option } #{ password_option } #{ archive_timeout_option } " +
        "#{ external_directories } #{ connectivity_options } #{ compression_options } #{ remote_options } " +
        "#{ remote_options } #{ retention_options } #{ pinning_options } #{ logging_options } #{ user_options }"
      end

      def password_env
        "PGPASSWORD=#{ Shellwords.escape(password) } " if password
      end

      def password_option
        # do not prompt for password
        '--no-password'
      end

      def sudo_option
        "#{ utility(:sudo) } -n -H -u #{ sudo_user }" if sudo_user
      end

      def connectivity_options
        return "--pgdatabase=#{ backup_db }" if socket

        opts = [
            "--pgdatabase=#{ backup_db }"
        ]
        opts << "--pghost='#{ host }'" if host
        opts << "--pgport=#{ port }" if port
        opts << "--pguser=#{ Shellwords.escape(username) }" if username
        opts.join(' ')
      end

      def compression_options
        "--compress-algorithm=#{compress_algorithm} --compress-level=#{compress_level.to_i}" unless compress_algorithm.to_sym == :none
      end

      def remote_options
        unless remote_proto.to_sym == :none
          opts = [
              "--remote-proto=#{remote_proto}",
              "--remote-host=#{Shellwords.escape(remote_host)}",
              "--remote-port=#{remote_port.to_i}",
              "--remote-user=#{Shellwords.escape(remote_user)}",
              "--remote-path=#{Shellwords.escape(remote_path)}"
          ]
          opts << "--ssh-options=#{Shellwords.escape(remote_ssh_options)}" unless remote_ssh_options.to_s.empty?
          opts.join(' ')
        end
      end

      def retention_options
        opts = []

        opts << "--retention-redundancy=#{retention_redundancy.to_i}" if retention_redundancy.to_i > 0
        opts << "--retention-window=#{retention_window.to_i}" if retention_window.to_i > 0
        opts << "--wal-depth=#{retention_wal_depth.to_i}" if retention_wal_depth.to_i > 0
        opts << '--delete-wal' if retention_delete_wal
        opts << '--delete-expired' if retention_delete_expired
        opts << '--merge-expired' if retention_merge_expired
        opts << '--dry-run' if retention_dry_run

        opts.join(' ')
      end

      def pinning_options
        opts = []

        opts << "--ttl=#{pinning_ttl.to_s}" if pinning_ttl
        opts << "--expire-time='#{pinning_expire_time.to_s}'" if pinning_expire_time

        opts.join(' ')
      end

      def logging_options
        opts = [
            "--log-level-console=#{log_level_console}",
            "--log-level-file=#{log_level_file}",
        ]

        opts << "--log-filename='#{Shellwords.escape(log_filename)}'" if log_filename
        opts << "--error-log-filename='#{Shellwords.escape(error_log_filename)}'" if error_log_filename
        opts << "--log-directory='#{Shellwords.escape(log_directory)}'" if log_directory
        opts << "--log-rotation-size=#{log_rotation_size}" if log_rotation_size
        opts << "--log-rotation-age=#{log_rotation_age}" if log_rotation_age

        opts.join(' ')
      end

      def mode_option
        "-b #{mode.upcase}"
      end

      def instance_name
        "--instance #{ Shellwords.escape(name) }"
      end

      def backup_catalog_option
        "-B '#{catalog}'"
      end

      def user_options
        Array(additional_options).join(' ')
      end

      def external_directories
        "--external-dirs=#{Array(external_dirs).join(':')}" unless Array(external_dirs).empty?
      end

      def stream_mode_option
        '--stream --temp-slot' if stream_mode
      end

      def threads_option
        "--threads=#{threads.to_i}"
      end

      def smooth_checkpoint_option
        '--smooth-checkpoint' if smooth_checkpoint
      end

      def backup_pg_log_option
        '--backup-pg-log' if backup_pg_log
      end

      def archive_timeout_option
        "--archive-timeout=#{archive_timeout.to_i}"
      end

      def no_validate_option
        '--no-validate' if no_validate
      end

      def skip_block_validation_option
        '--skip-block-validation' if skip_block_validation
      end

    end
  end
end
