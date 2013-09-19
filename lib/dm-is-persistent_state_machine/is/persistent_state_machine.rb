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
  property :name,           String, :required => true, :unique => true, :unique_index => true
  property :editable,       Boolean, :default => true
  property :sorter,         Integer
  property :type,           Discriminator

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
  property :name, String, :required => true, :unique => true, :unique_index => true
  property :type, Discriminator
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
    end
    
    def check(method_name)
      @checks << method_name
    end
    
    def checks
      @checks
    end
  end
  
  def set(name, value)
    instance_variable_set(name, value)
  end

  def folder(name, opts, &block)
    @folders = [] unless @folders
    if block_given?
      metaclass.instance_eval do
        opts[:filter_method] = 'filter_'+name.to_s
        define_method('filter_'+name.to_s) {
          yield
        }
      end
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
    @editable_data = {} unless @editable_data
    @editable_data[state.to_s] = [] unless @editable_data[state.to_s]
    @editable_data[state.to_s].push opts
  end
  
  def items_in(base_set, folder_name)
    folder = @folders.select{|f| f[:name] == folder_name.to_s }.first
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
  
  def state_folders
    return @folders.map{|f| {:name => f[:name], :label => f[:label] || f[:name] } }
  end
  
  def event_allowed?(event_name, from)
    return true unless @event_preconditions[event_name.to_s] && @event_preconditions[event_name.to_s][from.to_s]
    @event_preconditions[event_name.to_s][from.to_s].checks.each do |c|
      return false unless self.send(c.to_s)
    end
    true
  end
  
  def get_editable_data(state)
    return[] unless @editable_data[state.to_s]
    result = []
    @editable_data[state.to_s].each do |ed|
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
        belongs_to :state
        
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
          property :comment, String
          property Extlib::Inflection.foreign_key(target_model_name).to_sym, Integer, :required => true, :min => 1
          property :created_at, DateTime

          # associations
          belongs_to :user
          belongs_to :from, "State"
          belongs_to :to,   "State"
          belongs_to target_model_name.to_sym
        end
        
        state_change_model = Object.full_const_set(self.to_s+"StateChange",state_change_model)
        
        self_cached = self
        
        after :save do
          if (@prev_state && @prev_state != state)
            @state_change = state_change_model.create(:from => @prev_state, :to => state, :created_at => DateTime.now, :user => @updating_user, :comment => @comment, Extlib::Inflection.foreign_key(target_model_name).to_sym => self.id)
            @prev_state = nil # clean up cache
            @user = nil
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
        def trigger_event!(event_code, user, comment = nil)
          # cache prev_state and the user that is triggering the event
          @prev_state = self.state
          @updating_user = user
          @comment = comment

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