class StateTransition
  include DataMapper::Resource

  property :id,             Serial

  property :state_id,       Integer, :required => true, :min => 1
  property :target_id,      Integer, :required => true, :min => 1
  property :state_event_id, Integer, :required => true, :min => 1

  belongs_to :state
  belongs_to :target, 'State', :child_key => [:target_id]
  belongs_to :state_event
end

class State
  include DataMapper::Resource

  property :id,             Serial
  property :code,           String, :required => true, :unique => true, :unique_index => true
  property :editable,       Boolean, :default => true
  property :sorter,         Integer
  property :type,           Discriminator

  translatable :accepts_nested_attributes => false do
    property :name, String, :required => true, :unique_index => :name
    add_locale_tag_unique_index(:name)
  end

  # outgoing transitions
  has n, :state_transitions, 'StateTransition', :child_key => [:state_id]

  def events
    evts = []
    state_transitions.each do |transition|
      # uses the generic event method
      evts << transition.state_event
    end
    evts
  end

  # obj is the caller object
  def trigger_event!(obj, event_code)
    event = StateEvent.first(:code => event_code)
    puts event.inspect
    state_transitions.each do |transition|
      if transition.state_event == event
        obj.state = transition.target
        obj.after_trigger_event(event)
        return true
      end
    end
    return false
  end
end

class StateEvent
  include DataMapper::Resource

  property :id,   Serial
  property :code, String, :required => true, :unique => true, :unique_index => true
  property :next_user_required, Boolean
  property :comment_required, Boolean
  property :type, Discriminator

  translatable :accepts_nested_attributes => false do
    property :name, String, :required => true, :unique_index => :name
    add_locale_tag_unique_index(:name)
  end
end

# don't know why, but according to http://ryanangilly.com/post/234897271/dynamically-adding-class-methods-in-ruby that's the way to go for dynamically defining class methods
class Object
  def metaclass
    class << self; self; end
  end
end

module WorkflowConfig

  class EventPrecondition
    def initialize(name, opts)
      @name = name
      @from = opts[:from]
      @checks = []
      @validations = []
      @hints = []
      @never = false
    end

    def check(method_name)
      @never = true if method_name.eql?(:never)

      @checks << method_name
    end

    def validate(method_name)
      @validations << method_name
    end

    def hint(params)
      @hints << params
    end

    def checks
      @checks
    end

    def validations
      @validations
    end

    def hints
      @hints
    end

    def never?
      @never
    end

    def always?
      !@never && @checks.empty? && @hints.empty?
    end
  end

  module Setup
    attr_accessor :folders
    attr_accessor :event_preconditions
    attr_accessor :editable_data_defs
    attr_accessor :visible_data_defs

    def folder(name, opts, &block)
      @folders = [] unless @folders
      if block_given?
        opts[:filter_method] = 'filter_'+name.to_s
        define_method('filter_'+name.to_s, &block)
      end
      @folders << opts.merge(:name => name.to_s)
    end

    def preconditions_for(name, opts, &block)
      @event_preconditions = {} unless @event_preconditions
      @event_preconditions[name.to_s] = {} unless @event_preconditions[name.to_s]

      e = EventPrecondition.new(name.to_s, opts)

      if block_given?
        yield e
      end
      @event_preconditions[name.to_s][opts[:from].to_s] = e
    end

    def editable_data(state, opts, &block)
      @editable_data_defs = {} unless @editable_data_defs
      @editable_data_defs[state.to_s] = [] unless @editable_data_defs[state.to_s]
      @editable_data_defs[state.to_s].push opts
    end

     def visible_data(state, opts, &block)
      @visible_data_defs = {} unless @visible_data_defs
      @visible_data_defs[state.to_s] = [] unless @visible_data_defs[state.to_s]
      @visible_data_defs[state.to_s].push opts
    end

    def state_folders
      @folders.map{|f| { :name => f[:name], :label => f[:label] || f[:name] } }
    end
  end

  module Query

    def set(name, value)
      instance_variable_set(name, value)
    end

    def items_in(base_set, folder_name)
      folder = self.class.folders.select{|f| f[:name] == folder_name.to_s }.first
      if folder[:filter_method]
        result = self.send(folder[:filter_method].to_s, base_set)
      else
        result = base_set
      end
      if folder[:states]
        result = result.all('state.code' => folder[:states].map{|s| s.to_s})
      end
      result
    end

    def event_allowed?(event_name, from, opts = {})
      responsible_user_id = @quote.current_responsible_user_id
      return false unless responsible_user_id.nil? ||
        responsible_user_id == @user.id ||
        opts[:ignore_responsible_user_setting]

      return true unless self.class.event_preconditions
      return false unless self.class.event_preconditions[event_name.to_s]

      pre = self.class.event_preconditions[event_name.to_s][from.to_s]
      return false unless pre
      return false if pre.never?
      return true if pre.always?

      params = pre.hints.inject(&:merge) || {}
      params.merge!(:id => @user.id)

      # check user hints
      return false unless User.first(params)

      pre.checks.all? { |c| self.send(c.to_s) }
    end

    def get_validation_error(event_name, from)
      return nil unless self.class.event_preconditions && self.class.event_preconditions[event_name.to_s] && self.class.event_preconditions[event_name.to_s][from.to_s]
      self.class.event_preconditions[event_name.to_s][from.to_s].validations.each do |v|
        e = self.send(v.to_s)
        return e if e
      end
      nil
    end

    def get_editable_data(state)
      return[] unless self.class.editable_data_defs && self.class.editable_data_defs[state.to_s]
      result = []
      self.class.editable_data_defs[state.to_s].each do |ed|
        passed = true
        if ed[:checks]
          ed[:checks].each do |c|
            passed = false unless self.send(c.to_s)
          end
        end
        result += ed[:fields] if passed
      end
      result.uniq
    end

    def get_visible_data(state)
      return[] unless self.class.visible_data_defs && self.class.visible_data_defs[state.to_s]
      result = []
      self.class.visible_data_defs[state.to_s].each do |ed|
        passed = true
        if ed[:checks]
          ed[:checks].each do |c|
            passed = false unless self.send(c.to_s)
          end
        end
        result += ed[:fields] if passed
      end
      result.uniq
    end
  end

end

module DataMapper
  module Is
    module PersistentStateMachine

      class DmIsPersistentStateMachineException < Exception; end

      ##
      # fired when plugin gets included into Resource
      #
      def self.included(base)

      end

      ##
      # Methods that should be included in DataMapper::Model.
      # Normally this should just be your generator, so that the namespace
      # does not get cluttered. ClassMethods and InstanceMethods gets added
      # in the specific resources when you fire is :example
      ##

      def is_persistent_state_machine
        DataMapper.logger.info "registering persistent state machine..."

        # Add class-methods
        extend DataMapper::Is::PersistentStateMachine::ClassMethods
        extend Forwardable
        # Add instance-methods
        include DataMapper::Is::PersistentStateMachine::InstanceMethods

        target_model_name = self.name.snake_case

        # target object must have a status associated
        property :state_id, Integer, :required => true, :min => 1
        property :current_responsible_user_id, Integer
        belongs_to :state
        belongs_to :current_responsible_user, :model => 'User'

        has n, Extlib::Inflection.pluralize(target_model_name+"StateChange").snake_case.to_sym, :constraint => :destroy!

        # generate a FooState class that is derived from State        
        state_model = Object.full_const_set(self.to_s+"State", Class.new(State))
        # generate a FooStateEvent class that is derived from StateEvent
        event_model = Object.full_const_set(self.to_s+"StateEvent", Class.new(StateEvent))

        state_change_model = Class.new do
          include DataMapper::Resource

          property :id, ::DataMapper::Property::Serial

          property :from_id, Integer,   :required => true, :min => 1
          property :to_id, Integer,     :required => true, :min => 1
          property :user_id, Integer,   :required => true, :min => 1
          property :state_event_id, Integer
          property :comment, String, :length => 512, :required => false
          property Extlib::Inflection.foreign_key(target_model_name).to_sym, Integer, :required => true, :min => 1
          property :created_at, DateTime
          property :snapshot_data, ::DataMapper::Property::Text, :length => 1000000000
          property :next_user_id, Integer
          property :reverted, ::DataMapper::Property::Boolean, :default => false

          # associations
          belongs_to :user
          belongs_to :from, "State"
          belongs_to :to,   "State"
          belongs_to :state_event, "StateEvent"
          belongs_to target_model_name.to_sym
        end

        state_change_model = Object.full_const_set(self.to_s+"StateChange",state_change_model)

        self_cached = self

        after :save do
          if @prev_state
            snapshot_data = nil
            if self.respond_to?('serialize')
              snapshot_data = self.serialize
            end
            @state_change = state_change_model.new
            # for some reason attributes= does raise an error, unfortunately solution provided here https://github.com/datamapper/dm-core/issues/159 does not solve it
            @state_change.from = @prev_state
            @state_change.to = state
            @state_change.user = @updating_user
            @state_change.state_event_id = @state_event_id
            @state_change.comment = @comment
            @state_change.send(Extlib::Inflection.foreign_key(target_model_name)+'=', self.id)
            @state_change.snapshot_data = snapshot_data
            @state_change.next_user_id = @next_user_id
            @state_change.save
            @prev_state = nil # clean up cache
            @updating_user = nil
          end
        end

        # define delegators
        def_delegators :@state, :events
      end

      ##
      # fired after trigger_event! is called on resource
      #
      module ClassMethods

      end # ClassMethods

      module InstanceMethods
        def trigger_event!(event_code, user, comment = nil, next_user_id = nil)
          # cache prev_state and the user that is triggering the event
          @prev_state = self.state
          @updating_user = user
          @comment = comment
          @next_user_id = next_user_id
          @state_event_id = StateEvent.first(:code => event_code).id
          self.current_responsible_user_id = next_user_id

          # delegate to State#trigger!
          self.state.trigger_event!(self, event_code)
        end

        # hookable
        def after_trigger_event(event)

        end
      end # InstanceMethods
    end # PersistentStateMachine
  end # Is
end # DataMapper
