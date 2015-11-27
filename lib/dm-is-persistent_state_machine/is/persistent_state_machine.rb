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
    end
    
    def check(method_name)
      @checks << method_name
    end
    
    def validate(method_name)
      @validations << method_name
    end
    
    def checks
      @checks
    end
    
    def validations
      @validations
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
        define_method('filter_'+name.to_s) {|base_set|
          yield base_set
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
  
   def visible_data(state, opts, &block)
    @visible_data = {} unless @visible_data
    @visible_data[state.to_s] = [] unless @visible_data[state.to_s]
    @visible_data[state.to_s].push opts
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
  
  def event_allowed?(event_name, from, opts = {})
    return false unless @quote.current_responsible_user_id==nil || @quote.current_responsible_user_id==@user.id || opts[:ignore_responsible_user_setting]
    return true unless @event_preconditions && @event_preconditions[event_name.to_s] && @event_preconditions[event_name.to_s][from.to_s]
    @event_preconditions[event_name.to_s][from.to_s].checks.each do |c|
      return false unless self.send(c.to_s)
    end
    true
  end
  
  def get_validation_error(event_name, from)
    return nil unless @event_preconditions && @event_preconditions[event_name.to_s] && @event_preconditions[event_name.to_s][from.to_s]
    @event_preconditions[event_name.to_s][from.to_s].validations.each do |v|
      e = self.send(v.to_s)
      return e if e
    end
    nil
  end
  
  def get_editable_data(state)
    return[] unless @editable_data && @editable_data[state.to_s]
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
  
  def get_visible_data(state)
    return[] unless @visible_data && @visible_data[state.to_s]
    result = []
    @visible_data[state.to_s].each do |ed|
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
        
        target_model_name = Extlib::Inflection.underscore(self.name)
        
        # target object must have a status associated
        property :state_id, Integer, :required => true, :min => 1
        property :current_responsible_user_id, Integer
        belongs_to :state
        belongs_to :current_responsible_user, :model => 'User'
        
        state_changes = Extlib::Inflection.pluralize(target_model_name+"StateChange")
        state_changes = Extlib::Inflection.underscore(state_changes)
        has n, state_changes.to_sym, :constraint => :destroy!
        
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
          property :snapshot_data, ::DataMapper::Property::Text
          property :next_user_id, Integer

          # associations
          belongs_to :user
          belongs_to :from, "State"
          belongs_to :to,   "State"
          belongs_to target_model_name.to_sym
        end
        
        state_change_model = Object.full_const_set(self.to_s+"StateChange",state_change_model)
        
        self_cached = self
        
        after :save do
          if (@prev_state && (@prev_state != state || @next_user_id!=current_responsible_user_id))
            snapshot_data = nil
            if self.respond_to?('serialize')
              snapshot_data = self.serialize
            end
            @state_change = state_change_model.new
            # for some reason attributes= does raise an error, unfortunately solution provided here https://github.com/datamapper/dm-core/issues/159 does not solve it
            @state_change.from = @prev_state
            @state_change.to = state
            @state_change.created_at = DateTime.now,
            @state_change.user = @updating_user
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
